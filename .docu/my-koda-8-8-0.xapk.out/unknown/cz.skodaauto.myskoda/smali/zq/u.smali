.class public final Lzq/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/text/TextWatcher;


# instance fields
.field public d:I

.field public final synthetic e:Landroid/widget/EditText;

.field public final synthetic f:Lcom/google/android/material/textfield/TextInputLayout;


# direct methods
.method public constructor <init>(Lcom/google/android/material/textfield/TextInputLayout;Landroid/widget/EditText;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzq/u;->f:Lcom/google/android/material/textfield/TextInputLayout;

    .line 5
    .line 6
    iput-object p2, p0, Lzq/u;->e:Landroid/widget/EditText;

    .line 7
    .line 8
    invoke-virtual {p2}, Landroid/widget/TextView;->getLineCount()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iput p1, p0, Lzq/u;->d:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final afterTextChanged(Landroid/text/Editable;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lzq/u;->f:Lcom/google/android/material/textfield/TextInputLayout;

    .line 2
    .line 3
    iget-boolean v1, v0, Lcom/google/android/material/textfield/TextInputLayout;->N1:Z

    .line 4
    .line 5
    xor-int/lit8 v1, v1, 0x1

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-virtual {v0, v1, v2}, Lcom/google/android/material/textfield/TextInputLayout;->w(ZZ)V

    .line 9
    .line 10
    .line 11
    iget-boolean v1, v0, Lcom/google/android/material/textfield/TextInputLayout;->o:Z

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Lcom/google/android/material/textfield/TextInputLayout;->p(Landroid/text/Editable;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-boolean v1, v0, Lcom/google/android/material/textfield/TextInputLayout;->w:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-virtual {v0, p1}, Lcom/google/android/material/textfield/TextInputLayout;->x(Landroid/text/Editable;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    iget-object p1, p0, Lzq/u;->e:Landroid/widget/EditText;

    .line 26
    .line 27
    invoke-virtual {p1}, Landroid/widget/TextView;->getLineCount()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    iget v2, p0, Lzq/u;->d:I

    .line 32
    .line 33
    if-eq v1, v2, :cond_3

    .line 34
    .line 35
    if-ge v1, v2, :cond_2

    .line 36
    .line 37
    invoke-virtual {p1}, Landroid/view/View;->getMinimumHeight()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    iget v0, v0, Lcom/google/android/material/textfield/TextInputLayout;->G1:I

    .line 42
    .line 43
    if-eq v2, v0, :cond_2

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Landroid/view/View;->setMinimumHeight(I)V

    .line 46
    .line 47
    .line 48
    :cond_2
    iput v1, p0, Lzq/u;->d:I

    .line 49
    .line 50
    :cond_3
    return-void
.end method

.method public final beforeTextChanged(Ljava/lang/CharSequence;III)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onTextChanged(Ljava/lang/CharSequence;III)V
    .locals 0

    .line 1
    return-void
.end method
