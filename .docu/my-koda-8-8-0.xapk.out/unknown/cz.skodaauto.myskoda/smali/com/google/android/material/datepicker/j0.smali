.class public final Lcom/google/android/material/datepicker/j0;
.super Lcom/google/android/material/datepicker/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic l:Lcom/google/android/material/datepicker/x;

.field public final synthetic m:Lcom/google/android/material/textfield/TextInputLayout;

.field public final synthetic n:Lcom/google/android/material/datepicker/k0;


# direct methods
.method public constructor <init>(Lcom/google/android/material/datepicker/k0;Ljava/lang/String;Ljava/text/SimpleDateFormat;Lcom/google/android/material/textfield/TextInputLayout;Lcom/google/android/material/datepicker/c;Lcom/google/android/material/datepicker/x;Lcom/google/android/material/textfield/TextInputLayout;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/material/datepicker/j0;->n:Lcom/google/android/material/datepicker/k0;

    .line 2
    .line 3
    iput-object p6, p0, Lcom/google/android/material/datepicker/j0;->l:Lcom/google/android/material/datepicker/x;

    .line 4
    .line 5
    iput-object p7, p0, Lcom/google/android/material/datepicker/j0;->m:Lcom/google/android/material/textfield/TextInputLayout;

    .line 6
    .line 7
    invoke-direct {p0, p2, p3, p4, p5}, Lcom/google/android/material/datepicker/f;-><init>(Ljava/lang/String;Ljava/text/SimpleDateFormat;Lcom/google/android/material/textfield/TextInputLayout;Lcom/google/android/material/datepicker/c;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/j0;->m:Lcom/google/android/material/textfield/TextInputLayout;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputLayout;->getError()Ljava/lang/CharSequence;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/material/datepicker/j0;->l:Lcom/google/android/material/datepicker/x;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/x;->a()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final b(Ljava/lang/Long;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/j0;->n:Lcom/google/android/material/datepicker/k0;

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    iput-object p1, v0, Lcom/google/android/material/datepicker/k0;->d:Ljava/lang/Long;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iput-object p1, v0, Lcom/google/android/material/datepicker/k0;->d:Ljava/lang/Long;

    .line 10
    .line 11
    :goto_0
    iget-object p0, p0, Lcom/google/android/material/datepicker/j0;->l:Lcom/google/android/material/datepicker/x;

    .line 12
    .line 13
    iget-object p1, v0, Lcom/google/android/material/datepicker/k0;->d:Ljava/lang/Long;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/x;->b(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method
