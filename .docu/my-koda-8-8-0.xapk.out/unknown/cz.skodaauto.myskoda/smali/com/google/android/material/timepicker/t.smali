.class public final Lcom/google/android/material/timepicker/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/material/timepicker/o;


# instance fields
.field public final d:Landroid/widget/LinearLayout;

.field public final e:Lcom/google/android/material/timepicker/l;

.field public final f:Lcom/google/android/material/timepicker/q;

.field public final g:Lcom/google/android/material/timepicker/q;

.field public final h:Lcom/google/android/material/timepicker/ChipTextInputComboView;

.field public final i:Lcom/google/android/material/timepicker/ChipTextInputComboView;

.field public final j:Landroid/widget/EditText;

.field public final k:Landroid/widget/EditText;

.field public final l:Lcom/google/android/material/button/MaterialButtonToggleGroup;


# direct methods
.method public constructor <init>(Landroid/widget/LinearLayout;Lcom/google/android/material/timepicker/l;)V
    .locals 13

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/google/android/material/timepicker/q;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, v1}, Lcom/google/android/material/timepicker/q;-><init>(Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/material/timepicker/t;->f:Lcom/google/android/material/timepicker/q;

    .line 11
    .line 12
    new-instance v1, Lcom/google/android/material/timepicker/q;

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    invoke-direct {v1, p0, v2}, Lcom/google/android/material/timepicker/q;-><init>(Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lcom/google/android/material/timepicker/t;->g:Lcom/google/android/material/timepicker/q;

    .line 19
    .line 20
    iput-object p1, p0, Lcom/google/android/material/timepicker/t;->d:Landroid/widget/LinearLayout;

    .line 21
    .line 22
    iput-object p2, p0, Lcom/google/android/material/timepicker/t;->e:Lcom/google/android/material/timepicker/l;

    .line 23
    .line 24
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    const v3, 0x7f0a01c4

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, v3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    check-cast v3, Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 36
    .line 37
    iput-object v3, p0, Lcom/google/android/material/timepicker/t;->h:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 38
    .line 39
    const v4, 0x7f0a01c1

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    check-cast v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 47
    .line 48
    iput-object v4, p0, Lcom/google/android/material/timepicker/t;->i:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 49
    .line 50
    const v5, 0x7f0a01c3

    .line 51
    .line 52
    .line 53
    invoke-virtual {v3, v5}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    iget-object v7, v3, Lcom/google/android/material/timepicker/ChipTextInputComboView;->e:Lcom/google/android/material/textfield/TextInputLayout;

    .line 58
    .line 59
    check-cast v6, Landroid/widget/TextView;

    .line 60
    .line 61
    invoke-virtual {v4, v5}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    iget-object v8, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->e:Lcom/google/android/material/textfield/TextInputLayout;

    .line 66
    .line 67
    check-cast v5, Landroid/widget/TextView;

    .line 68
    .line 69
    const v9, 0x7f120726

    .line 70
    .line 71
    .line 72
    invoke-virtual {v2, v9}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v10

    .line 76
    invoke-virtual {v6, v10}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 77
    .line 78
    .line 79
    const/4 v10, 0x2

    .line 80
    invoke-virtual {v6, v10}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 81
    .line 82
    .line 83
    const v6, 0x7f120725

    .line 84
    .line 85
    .line 86
    invoke-virtual {v2, v6}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v11

    .line 90
    invoke-virtual {v5, v11}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v5, v10}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 94
    .line 95
    .line 96
    const/16 v5, 0xc

    .line 97
    .line 98
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 99
    .line 100
    .line 101
    move-result-object v5

    .line 102
    const v10, 0x7f0a0290

    .line 103
    .line 104
    .line 105
    invoke-virtual {v3, v10, v5}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setTag(ILjava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    const/16 v5, 0xa

    .line 109
    .line 110
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    invoke-virtual {v4, v10, v5}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setTag(ILjava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    iget v5, p2, Lcom/google/android/material/timepicker/l;->f:I

    .line 118
    .line 119
    if-nez v5, :cond_0

    .line 120
    .line 121
    const v5, 0x7f0a01c0

    .line 122
    .line 123
    .line 124
    invoke-virtual {p1, v5}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    check-cast v5, Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 129
    .line 130
    iput-object v5, p0, Lcom/google/android/material/timepicker/t;->l:Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 131
    .line 132
    new-instance v10, Lcom/google/android/material/timepicker/u;

    .line 133
    .line 134
    const/4 v11, 0x1

    .line 135
    invoke-direct {v10, p0, v11}, Lcom/google/android/material/timepicker/u;-><init>(Ljava/lang/Object;I)V

    .line 136
    .line 137
    .line 138
    iget-object v5, v5, Lcom/google/android/material/button/MaterialButtonToggleGroup;->n:Ljava/util/LinkedHashSet;

    .line 139
    .line 140
    invoke-virtual {v5, v10}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    iget-object v5, p0, Lcom/google/android/material/timepicker/t;->l:Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 144
    .line 145
    const/4 v10, 0x0

    .line 146
    invoke-virtual {v5, v10}, Landroid/view/View;->setVisibility(I)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/t;->f()V

    .line 150
    .line 151
    .line 152
    :cond_0
    new-instance v5, Lcom/google/android/material/timepicker/v;

    .line 153
    .line 154
    const/4 v10, 0x1

    .line 155
    invoke-direct {v5, p0, v10}, Lcom/google/android/material/timepicker/v;-><init>(Ljava/lang/Object;I)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v4, v5}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v3, v5}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 162
    .line 163
    .line 164
    iget-object v5, p2, Lcom/google/android/material/timepicker/l;->e:Lcom/google/android/material/timepicker/j;

    .line 165
    .line 166
    iget-object v10, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->f:Landroid/widget/EditText;

    .line 167
    .line 168
    invoke-virtual {v10}, Landroid/widget/TextView;->getFilters()[Landroid/text/InputFilter;

    .line 169
    .line 170
    .line 171
    move-result-object v11

    .line 172
    array-length v12, v11

    .line 173
    add-int/lit8 v12, v12, 0x1

    .line 174
    .line 175
    invoke-static {v11, v12}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v12

    .line 179
    check-cast v12, [Landroid/text/InputFilter;

    .line 180
    .line 181
    array-length v11, v11

    .line 182
    aput-object v5, v12, v11

    .line 183
    .line 184
    invoke-virtual {v10, v12}, Landroid/widget/TextView;->setFilters([Landroid/text/InputFilter;)V

    .line 185
    .line 186
    .line 187
    iget-object v5, p2, Lcom/google/android/material/timepicker/l;->d:Lcom/google/android/material/timepicker/j;

    .line 188
    .line 189
    iget-object v10, v3, Lcom/google/android/material/timepicker/ChipTextInputComboView;->f:Landroid/widget/EditText;

    .line 190
    .line 191
    invoke-virtual {v10}, Landroid/widget/TextView;->getFilters()[Landroid/text/InputFilter;

    .line 192
    .line 193
    .line 194
    move-result-object v11

    .line 195
    array-length v12, v11

    .line 196
    add-int/lit8 v12, v12, 0x1

    .line 197
    .line 198
    invoke-static {v11, v12}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v12

    .line 202
    check-cast v12, [Landroid/text/InputFilter;

    .line 203
    .line 204
    array-length v11, v11

    .line 205
    aput-object v5, v12, v11

    .line 206
    .line 207
    invoke-virtual {v10, v12}, Landroid/widget/TextView;->setFilters([Landroid/text/InputFilter;)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v8}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 211
    .line 212
    .line 213
    move-result-object v5

    .line 214
    iput-object v5, p0, Lcom/google/android/material/timepicker/t;->j:Landroid/widget/EditText;

    .line 215
    .line 216
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 217
    .line 218
    .line 219
    move-result-object v10

    .line 220
    new-instance v11, Lcom/google/android/material/timepicker/s;

    .line 221
    .line 222
    invoke-direct {v11, v10, v6}, Lcom/google/android/material/timepicker/s;-><init>(Landroid/content/res/Resources;I)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v5, v11}, Landroid/view/View;->setAccessibilityDelegate(Landroid/view/View$AccessibilityDelegate;)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v7}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 229
    .line 230
    .line 231
    move-result-object v6

    .line 232
    iput-object v6, p0, Lcom/google/android/material/timepicker/t;->k:Landroid/widget/EditText;

    .line 233
    .line 234
    invoke-virtual {p1}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 235
    .line 236
    .line 237
    move-result-object v10

    .line 238
    new-instance v11, Lcom/google/android/material/timepicker/s;

    .line 239
    .line 240
    invoke-direct {v11, v10, v9}, Lcom/google/android/material/timepicker/s;-><init>(Landroid/content/res/Resources;I)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v6, v11}, Landroid/view/View;->setAccessibilityDelegate(Landroid/view/View$AccessibilityDelegate;)V

    .line 244
    .line 245
    .line 246
    new-instance v9, Lcom/google/android/material/timepicker/p;

    .line 247
    .line 248
    invoke-direct {v9, v4, v3, p2}, Lcom/google/android/material/timepicker/p;-><init>(Lcom/google/android/material/timepicker/ChipTextInputComboView;Lcom/google/android/material/timepicker/ChipTextInputComboView;Lcom/google/android/material/timepicker/l;)V

    .line 249
    .line 250
    .line 251
    new-instance v10, Lcom/google/android/material/timepicker/r;

    .line 252
    .line 253
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 254
    .line 255
    .line 256
    move-result-object v11

    .line 257
    const/4 v12, 0x0

    .line 258
    invoke-direct {v10, v11, v2, p2, v12}, Lcom/google/android/material/timepicker/r;-><init>(Landroid/content/Context;Landroid/content/res/Resources;Lcom/google/android/material/timepicker/l;I)V

    .line 259
    .line 260
    .line 261
    iget-object v4, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->d:Lcom/google/android/material/chip/Chip;

    .line 262
    .line 263
    invoke-static {v4, v10}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 264
    .line 265
    .line 266
    new-instance v4, Lcom/google/android/material/timepicker/r;

    .line 267
    .line 268
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    const/4 v10, 0x1

    .line 273
    invoke-direct {v4, p1, v2, p2, v10}, Lcom/google/android/material/timepicker/r;-><init>(Landroid/content/Context;Landroid/content/res/Resources;Lcom/google/android/material/timepicker/l;I)V

    .line 274
    .line 275
    .line 276
    iget-object p1, v3, Lcom/google/android/material/timepicker/ChipTextInputComboView;->d:Lcom/google/android/material/chip/Chip;

    .line 277
    .line 278
    invoke-static {p1, v4}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v5, v1}, Landroid/widget/TextView;->addTextChangedListener(Landroid/text/TextWatcher;)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v6, v0}, Landroid/widget/TextView;->addTextChangedListener(Landroid/text/TextWatcher;)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {p0, p2}, Lcom/google/android/material/timepicker/t;->e(Lcom/google/android/material/timepicker/l;)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v8}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 291
    .line 292
    .line 293
    move-result-object p0

    .line 294
    invoke-virtual {v7}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 295
    .line 296
    .line 297
    move-result-object p1

    .line 298
    const p2, 0x10000005

    .line 299
    .line 300
    .line 301
    invoke-virtual {p0, p2}, Landroid/widget/TextView;->setImeOptions(I)V

    .line 302
    .line 303
    .line 304
    const p2, 0x10000006

    .line 305
    .line 306
    .line 307
    invoke-virtual {p1, p2}, Landroid/widget/TextView;->setImeOptions(I)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {p0, v9}, Landroid/widget/TextView;->setOnEditorActionListener(Landroid/widget/TextView$OnEditorActionListener;)V

    .line 311
    .line 312
    .line 313
    invoke-virtual {p0, v9}, Landroid/view/View;->setOnKeyListener(Landroid/view/View$OnKeyListener;)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {p1, v9}, Landroid/view/View;->setOnKeyListener(Landroid/view/View$OnKeyListener;)V

    .line 317
    .line 318
    .line 319
    return-void
.end method


# virtual methods
.method public final a(I)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/t;->e:Lcom/google/android/material/timepicker/l;

    .line 2
    .line 3
    iput p1, v0, Lcom/google/android/material/timepicker/l;->i:I

    .line 4
    .line 5
    const/16 v0, 0xc

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x1

    .line 9
    if-ne p1, v0, :cond_0

    .line 10
    .line 11
    move v0, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v0, v1

    .line 14
    :goto_0
    iget-object v3, p0, Lcom/google/android/material/timepicker/t;->h:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 15
    .line 16
    invoke-virtual {v3, v0}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 17
    .line 18
    .line 19
    const/16 v0, 0xa

    .line 20
    .line 21
    if-ne p1, v0, :cond_1

    .line 22
    .line 23
    move v1, v2

    .line 24
    :cond_1
    iget-object p1, p0, Lcom/google/android/material/timepicker/t;->i:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 25
    .line 26
    invoke-virtual {p1, v1}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/t;->f()V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/t;->d:Landroid/widget/LinearLayout;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lcom/google/android/material/timepicker/t;->e:Lcom/google/android/material/timepicker/l;

    .line 8
    .line 9
    iget v0, v0, Lcom/google/android/material/timepicker/l;->i:I

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lcom/google/android/material/timepicker/t;->a(I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final c()V
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/google/android/material/timepicker/t;->d:Landroid/widget/LinearLayout;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getFocusedChild()Landroid/view/View;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-class v2, Landroid/view/inputmethod/InputMethodManager;

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Landroid/view/inputmethod/InputMethodManager;

    .line 20
    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0}, Landroid/view/View;->getWindowToken()Landroid/os/IBinder;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-virtual {v1, v0, v2}, Landroid/view/inputmethod/InputMethodManager;->hideSoftInputFromWindow(Landroid/os/IBinder;I)Z

    .line 29
    .line 30
    .line 31
    :cond_0
    const/16 v0, 0x8

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Landroid/view/View;->setVisibility(I)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public final d()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/t;->e:Lcom/google/android/material/timepicker/l;

    .line 2
    .line 3
    iget v1, v0, Lcom/google/android/material/timepicker/l;->i:I

    .line 4
    .line 5
    const/16 v2, 0xc

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x1

    .line 9
    if-ne v1, v2, :cond_0

    .line 10
    .line 11
    move v1, v4

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v1, v3

    .line 14
    :goto_0
    iget-object v2, p0, Lcom/google/android/material/timepicker/t;->h:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 15
    .line 16
    invoke-virtual {v2, v1}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 17
    .line 18
    .line 19
    iget v0, v0, Lcom/google/android/material/timepicker/l;->i:I

    .line 20
    .line 21
    const/16 v1, 0xa

    .line 22
    .line 23
    if-ne v0, v1, :cond_1

    .line 24
    .line 25
    move v3, v4

    .line 26
    :cond_1
    iget-object p0, p0, Lcom/google/android/material/timepicker/t;->i:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 27
    .line 28
    invoke-virtual {p0, v3}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final e(Lcom/google/android/material/timepicker/l;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/t;->j:Landroid/widget/EditText;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/material/timepicker/t;->g:Lcom/google/android/material/timepicker/q;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->removeTextChangedListener(Landroid/text/TextWatcher;)V

    .line 6
    .line 7
    .line 8
    iget-object v2, p0, Lcom/google/android/material/timepicker/t;->k:Landroid/widget/EditText;

    .line 9
    .line 10
    iget-object v3, p0, Lcom/google/android/material/timepicker/t;->f:Lcom/google/android/material/timepicker/q;

    .line 11
    .line 12
    invoke-virtual {v2, v3}, Landroid/widget/TextView;->removeTextChangedListener(Landroid/text/TextWatcher;)V

    .line 13
    .line 14
    .line 15
    iget-object v4, p0, Lcom/google/android/material/timepicker/t;->d:Landroid/widget/LinearLayout;

    .line 16
    .line 17
    invoke-virtual {v4}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    invoke-virtual {v4}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    iget-object v4, v4, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    .line 26
    .line 27
    iget v5, p1, Lcom/google/android/material/timepicker/l;->h:I

    .line 28
    .line 29
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    const-string v6, "%02d"

    .line 38
    .line 39
    invoke-static {v4, v6, v5}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    invoke-virtual {p1}, Lcom/google/android/material/timepicker/l;->h()I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-static {v4, v6, p1}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iget-object v4, p0, Lcom/google/android/material/timepicker/t;->h:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 60
    .line 61
    iget-object v7, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->g:Lcom/google/android/material/timepicker/q;

    .line 62
    .line 63
    iget-object v8, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->f:Landroid/widget/EditText;

    .line 64
    .line 65
    invoke-virtual {v4}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 66
    .line 67
    .line 68
    move-result-object v9

    .line 69
    invoke-static {v9, v5, v6}, Lcom/google/android/material/timepicker/l;->a(Landroid/content/res/Resources;Ljava/lang/CharSequence;Ljava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    iget-object v4, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->d:Lcom/google/android/material/chip/Chip;

    .line 74
    .line 75
    invoke-virtual {v4, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 76
    .line 77
    .line 78
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    if-nez v4, :cond_0

    .line 83
    .line 84
    invoke-virtual {v8, v7}, Landroid/widget/TextView;->removeTextChangedListener(Landroid/text/TextWatcher;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v8, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v8, v7}, Landroid/widget/TextView;->addTextChangedListener(Landroid/text/TextWatcher;)V

    .line 91
    .line 92
    .line 93
    :cond_0
    iget-object v4, p0, Lcom/google/android/material/timepicker/t;->i:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 94
    .line 95
    iget-object v5, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->g:Lcom/google/android/material/timepicker/q;

    .line 96
    .line 97
    iget-object v7, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->f:Landroid/widget/EditText;

    .line 98
    .line 99
    invoke-virtual {v4}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 100
    .line 101
    .line 102
    move-result-object v8

    .line 103
    invoke-static {v8, p1, v6}, Lcom/google/android/material/timepicker/l;->a(Landroid/content/res/Resources;Ljava/lang/CharSequence;Ljava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    iget-object v4, v4, Lcom/google/android/material/timepicker/ChipTextInputComboView;->d:Lcom/google/android/material/chip/Chip;

    .line 108
    .line 109
    invoke-virtual {v4, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 110
    .line 111
    .line 112
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    if-nez v4, :cond_1

    .line 117
    .line 118
    invoke-virtual {v7, v5}, Landroid/widget/TextView;->removeTextChangedListener(Landroid/text/TextWatcher;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v7, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v7, v5}, Landroid/widget/TextView;->addTextChangedListener(Landroid/text/TextWatcher;)V

    .line 125
    .line 126
    .line 127
    :cond_1
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->addTextChangedListener(Landroid/text/TextWatcher;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2, v3}, Landroid/widget/TextView;->addTextChangedListener(Landroid/text/TextWatcher;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/t;->f()V

    .line 134
    .line 135
    .line 136
    return-void
.end method

.method public final f()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/t;->l:Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object p0, p0, Lcom/google/android/material/timepicker/t;->e:Lcom/google/android/material/timepicker/l;

    .line 7
    .line 8
    iget p0, p0, Lcom/google/android/material/timepicker/l;->j:I

    .line 9
    .line 10
    if-nez p0, :cond_1

    .line 11
    .line 12
    const p0, 0x7f0a01be

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    const p0, 0x7f0a01bf

    .line 17
    .line 18
    .line 19
    :goto_0
    const/4 v1, 0x1

    .line 20
    invoke-virtual {v0, p0, v1}, Lcom/google/android/material/button/MaterialButtonToggleGroup;->f(IZ)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final invalidate()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/t;->e:Lcom/google/android/material/timepicker/l;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lcom/google/android/material/timepicker/t;->e(Lcom/google/android/material/timepicker/l;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
