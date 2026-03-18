.class public final Lcom/google/android/material/datepicker/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lcom/google/android/material/datepicker/i;

.field public b:Lcom/google/android/material/datepicker/c;

.field public c:I

.field public d:Ljava/lang/String;

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/android/material/datepicker/i;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/google/android/material/datepicker/y;->c:I

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput-object v0, p0, Lcom/google/android/material/datepicker/y;->d:Ljava/lang/String;

    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/material/datepicker/y;->e:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v0, p0, Lcom/google/android/material/datepicker/y;->f:Ljava/lang/String;

    .line 13
    .line 14
    iput-object v0, p0, Lcom/google/android/material/datepicker/y;->g:Ljava/lang/Object;

    .line 15
    .line 16
    iput-object p1, p0, Lcom/google/android/material/datepicker/y;->a:Lcom/google/android/material/datepicker/i;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()Lcom/google/android/material/datepicker/z;
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/y;->b:Lcom/google/android/material/datepicker/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/material/datepicker/a;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/material/datepicker/a;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Lcom/google/android/material/datepicker/a;->a()Lcom/google/android/material/datepicker/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lcom/google/android/material/datepicker/y;->b:Lcom/google/android/material/datepicker/c;

    .line 15
    .line 16
    :cond_0
    iget v0, p0, Lcom/google/android/material/datepicker/y;->c:I

    .line 17
    .line 18
    iget-object v1, p0, Lcom/google/android/material/datepicker/y;->a:Lcom/google/android/material/datepicker/i;

    .line 19
    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    invoke-interface {v1}, Lcom/google/android/material/datepicker/i;->B()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iput v0, p0, Lcom/google/android/material/datepicker/y;->c:I

    .line 27
    .line 28
    :cond_1
    iget-object v0, p0, Lcom/google/android/material/datepicker/y;->g:Ljava/lang/Object;

    .line 29
    .line 30
    if-eqz v0, :cond_2

    .line 31
    .line 32
    invoke-interface {v1, v0}, Lcom/google/android/material/datepicker/i;->W(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_2
    iget-object v0, p0, Lcom/google/android/material/datepicker/y;->b:Lcom/google/android/material/datepicker/c;

    .line 36
    .line 37
    iget-object v2, v0, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 38
    .line 39
    if-nez v2, :cond_5

    .line 40
    .line 41
    invoke-interface {v1}, Lcom/google/android/material/datepicker/i;->l0()Ljava/util/ArrayList;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-nez v2, :cond_3

    .line 50
    .line 51
    invoke-interface {v1}, Lcom/google/android/material/datepicker/i;->l0()Ljava/util/ArrayList;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    check-cast v2, Ljava/lang/Long;

    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 66
    .line 67
    .line 68
    move-result-wide v2

    .line 69
    invoke-static {v2, v3}, Lcom/google/android/material/datepicker/b0;->c(J)Lcom/google/android/material/datepicker/b0;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    iget-object v3, p0, Lcom/google/android/material/datepicker/y;->b:Lcom/google/android/material/datepicker/c;

    .line 74
    .line 75
    iget-object v4, v3, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 76
    .line 77
    invoke-virtual {v2, v4}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 78
    .line 79
    .line 80
    move-result v4

    .line 81
    if-ltz v4, :cond_3

    .line 82
    .line 83
    iget-object v3, v3, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 84
    .line 85
    invoke-virtual {v2, v3}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    if-gtz v3, :cond_3

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_3
    new-instance v2, Lcom/google/android/material/datepicker/b0;

    .line 93
    .line 94
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    invoke-direct {v2, v3}, Lcom/google/android/material/datepicker/b0;-><init>(Ljava/util/Calendar;)V

    .line 99
    .line 100
    .line 101
    iget-object v3, p0, Lcom/google/android/material/datepicker/y;->b:Lcom/google/android/material/datepicker/c;

    .line 102
    .line 103
    iget-object v4, v3, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 104
    .line 105
    invoke-virtual {v2, v4}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    if-ltz v4, :cond_4

    .line 110
    .line 111
    iget-object v3, v3, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 112
    .line 113
    invoke-virtual {v2, v3}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    if-gtz v3, :cond_4

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_4
    iget-object v2, p0, Lcom/google/android/material/datepicker/y;->b:Lcom/google/android/material/datepicker/c;

    .line 121
    .line 122
    iget-object v2, v2, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 123
    .line 124
    :goto_0
    iput-object v2, v0, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 125
    .line 126
    :cond_5
    new-instance v0, Lcom/google/android/material/datepicker/z;

    .line 127
    .line 128
    invoke-direct {v0}, Lcom/google/android/material/datepicker/z;-><init>()V

    .line 129
    .line 130
    .line 131
    new-instance v2, Landroid/os/Bundle;

    .line 132
    .line 133
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 134
    .line 135
    .line 136
    const-string v3, "OVERRIDE_THEME_RES_ID"

    .line 137
    .line 138
    const/4 v4, 0x0

    .line 139
    invoke-virtual {v2, v3, v4}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 140
    .line 141
    .line 142
    const-string v3, "DATE_SELECTOR_KEY"

    .line 143
    .line 144
    invoke-virtual {v2, v3, v1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 145
    .line 146
    .line 147
    const-string v1, "CALENDAR_CONSTRAINTS_KEY"

    .line 148
    .line 149
    iget-object v3, p0, Lcom/google/android/material/datepicker/y;->b:Lcom/google/android/material/datepicker/c;

    .line 150
    .line 151
    invoke-virtual {v2, v1, v3}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 152
    .line 153
    .line 154
    const-string v1, "DAY_VIEW_DECORATOR_KEY"

    .line 155
    .line 156
    const/4 v3, 0x0

    .line 157
    invoke-virtual {v2, v1, v3}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 158
    .line 159
    .line 160
    const-string v1, "TITLE_TEXT_RES_ID_KEY"

    .line 161
    .line 162
    iget v5, p0, Lcom/google/android/material/datepicker/y;->c:I

    .line 163
    .line 164
    invoke-virtual {v2, v1, v5}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 165
    .line 166
    .line 167
    const-string v1, "TITLE_TEXT_KEY"

    .line 168
    .line 169
    iget-object v5, p0, Lcom/google/android/material/datepicker/y;->d:Ljava/lang/String;

    .line 170
    .line 171
    invoke-virtual {v2, v1, v5}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 172
    .line 173
    .line 174
    const-string v1, "INPUT_MODE_KEY"

    .line 175
    .line 176
    invoke-virtual {v2, v1, v4}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 177
    .line 178
    .line 179
    const-string v1, "POSITIVE_BUTTON_TEXT_RES_ID_KEY"

    .line 180
    .line 181
    invoke-virtual {v2, v1, v4}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 182
    .line 183
    .line 184
    const-string v1, "POSITIVE_BUTTON_TEXT_KEY"

    .line 185
    .line 186
    iget-object v5, p0, Lcom/google/android/material/datepicker/y;->e:Ljava/lang/String;

    .line 187
    .line 188
    invoke-virtual {v2, v1, v5}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 189
    .line 190
    .line 191
    const-string v1, "POSITIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY"

    .line 192
    .line 193
    invoke-virtual {v2, v1, v4}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 194
    .line 195
    .line 196
    const-string v1, "POSITIVE_BUTTON_CONTENT_DESCRIPTION_KEY"

    .line 197
    .line 198
    invoke-virtual {v2, v1, v3}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 199
    .line 200
    .line 201
    const-string v1, "NEGATIVE_BUTTON_TEXT_RES_ID_KEY"

    .line 202
    .line 203
    invoke-virtual {v2, v1, v4}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 204
    .line 205
    .line 206
    const-string v1, "NEGATIVE_BUTTON_TEXT_KEY"

    .line 207
    .line 208
    iget-object p0, p0, Lcom/google/android/material/datepicker/y;->f:Ljava/lang/String;

    .line 209
    .line 210
    invoke-virtual {v2, v1, p0}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 211
    .line 212
    .line 213
    const-string p0, "NEGATIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY"

    .line 214
    .line 215
    invoke-virtual {v2, p0, v4}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 216
    .line 217
    .line 218
    const-string p0, "NEGATIVE_BUTTON_CONTENT_DESCRIPTION_KEY"

    .line 219
    .line 220
    invoke-virtual {v2, p0, v3}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0, v2}, Landroidx/fragment/app/j0;->setArguments(Landroid/os/Bundle;)V

    .line 224
    .line 225
    .line 226
    return-object v0
.end method
