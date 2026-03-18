.class public final Lcom/google/android/material/datepicker/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/android/material/datepicker/q0;


# direct methods
.method public constructor <init>(Lcom/google/android/material/datepicker/q0;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/material/datepicker/o0;->e:Lcom/google/android/material/datepicker/q0;

    .line 5
    .line 6
    iput p2, p0, Lcom/google/android/material/datepicker/o0;->d:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 3

    .line 1
    iget-object p1, p0, Lcom/google/android/material/datepicker/o0;->e:Lcom/google/android/material/datepicker/q0;

    .line 2
    .line 3
    iget-object p1, p1, Lcom/google/android/material/datepicker/q0;->d:Lcom/google/android/material/datepicker/u;

    .line 4
    .line 5
    iget-object v0, p1, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 6
    .line 7
    iget v0, v0, Lcom/google/android/material/datepicker/b0;->e:I

    .line 8
    .line 9
    iget p0, p0, Lcom/google/android/material/datepicker/o0;->d:I

    .line 10
    .line 11
    invoke-static {p0, v0}, Lcom/google/android/material/datepicker/b0;->b(II)Lcom/google/android/material/datepicker/b0;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    iget-object v0, p1, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 16
    .line 17
    iget-object v1, v0, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 18
    .line 19
    iget-object v0, v0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-gez v2, :cond_0

    .line 26
    .line 27
    move-object p0, v0

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-virtual {p0, v1}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-lez v0, :cond_1

    .line 34
    .line 35
    move-object p0, v1

    .line 36
    :cond_1
    :goto_0
    invoke-virtual {p1, p0}, Lcom/google/android/material/datepicker/u;->j(Lcom/google/android/material/datepicker/b0;)V

    .line 37
    .line 38
    .line 39
    const/4 p0, 0x1

    .line 40
    invoke-virtual {p1, p0}, Lcom/google/android/material/datepicker/u;->k(I)V

    .line 41
    .line 42
    .line 43
    iget-object p0, p1, Lcom/google/android/material/datepicker/u;->q:Lcom/google/android/material/button/MaterialButton;

    .line 44
    .line 45
    if-eqz p0, :cond_2

    .line 46
    .line 47
    const/16 p1, 0x8

    .line 48
    .line 49
    invoke-virtual {p0, p1}, Landroid/view/View;->sendAccessibilityEvent(I)V

    .line 50
    .line 51
    .line 52
    :cond_2
    return-void
.end method
