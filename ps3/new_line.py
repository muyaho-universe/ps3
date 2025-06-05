from unidiff.patch import Line

class NewLine(Line):
    def __init__(self, *args, parent_line_no=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.parent_line_no = parent_line_no
