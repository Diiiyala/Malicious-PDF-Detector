import logging, pikepdf
from io import BytesIO
from pypdf import PdfReader

MAX_EXPANDED_MB = 200
MAX_EXPANDED_BYTES = MAX_EXPANDED_MB * 1024 * 1024

logger = logging.getLogger(__name__)


def load_pdf(raw_file_content: bytes, filename: str = ""):

    file_stream = BytesIO(raw_file_content)
    reader = None
    findings = []
    content = raw_file_content

    try:
        reader = PdfReader(file_stream, strict=False)
        _ = len(reader.pages)

    except Exception as e:
        logger.warning(
            "Metadata/Structure parsing failed for %s: %s", filename, e
        )

        try:
            with pikepdf.open(BytesIO(raw_file_content)) as pdf:
                extracted = bytearray(raw_file_content)
                budget = MAX_EXPANDED_BYTES - len(extracted)

                for obj in pdf.objects:
                    if budget <= 0:
                        logger.warning(
                            "Decompressed content for %s hit the %d MB "
                            "analysis cap; remaining streams skipped",
                            filename,
                            MAX_EXPANDED_MB,
                        )
                        break

                    if not isinstance(obj, pikepdf.Stream):
                        continue

                    try:
                        data = obj.read_bytes()
                    except Exception as e:
                        logger.debug(
                            "Could not read stream object during repair: %s", e
                        )
                        continue

                    extracted.extend(data[:budget])
                    budget -= len(data)

                repaired = BytesIO()
                pdf.save(repaired, static_id=True)

                content = bytes(extracted)
                file_stream = BytesIO(repaired.getvalue())
                reader = PdfReader(file_stream, strict=False)

                try:
                    _ = len(reader.pages)
                except Exception as e:
                    logger.debug("Repaired PDF still unreadable: %s", e)
                    reader = None

                findings.append(
                    "ALERT: Malformed structure repaired and analyzed"
                )

        except Exception as e:
            logger.error("Deep repair failed: %s", e)
            findings.append(
                "ALERT: Malformed PDF structure detected "
                "(Potential Evasion/Corruption)"
            )

    return reader, file_stream, content, findings
