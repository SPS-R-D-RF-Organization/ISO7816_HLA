from saleae.analyzers import AnalyzerFrame


class APDU_Frame:

    def __init__(self, title: str, type: str, data: str, hexString: str, frame1, frame2=None):
        self.title = title
        self.type = type
        self.data = data
        self.hexString = hexString
        self.inputFrame1 = frame1
        self.inputFrame2 = frame2

    def getOutputFrame(self):
        if self.inputFrame2 is not None:
            return AnalyzerFrame(self.title, self.inputFrame1.start_time, self.inputFrame2.end_time, {
                'category': self.type,
                'transmitted_data': self.data,
                'hex': self.hexString
            })
        else:
            return AnalyzerFrame(self.title, self.inputFrame1.start_time, self.inputFrame1.end_time, {
                'category': self.type,
                'transmitted_data': self.data,
                'hex': self.hexString
            })
