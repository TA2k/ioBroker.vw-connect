.class public interface abstract Lcom/google/android/material/datepicker/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# direct methods
.method public static varargs e0([Landroid/widget/EditText;)V
    .locals 5

    .line 1
    array-length v0, p0

    .line 2
    if-nez v0, :cond_0

    .line 3
    .line 4
    return-void

    .line 5
    :cond_0
    new-instance v0, Lcom/google/android/material/datepicker/g;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p0, v1}, Lcom/google/android/material/datepicker/g;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    array-length v1, p0

    .line 12
    const/4 v2, 0x0

    .line 13
    move v3, v2

    .line 14
    :goto_0
    if-ge v3, v1, :cond_1

    .line 15
    .line 16
    aget-object v4, p0, v3

    .line 17
    .line 18
    invoke-virtual {v4, v0}, Landroid/view/View;->setOnFocusChangeListener(Landroid/view/View$OnFocusChangeListener;)V

    .line 19
    .line 20
    .line 21
    add-int/lit8 v3, v3, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    aget-object p0, p0, v2

    .line 25
    .line 26
    new-instance v0, Lcom/google/android/material/datepicker/h;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-direct {v0, p0, v1}, Lcom/google/android/material/datepicker/h;-><init>(Landroid/view/View;I)V

    .line 30
    .line 31
    .line 32
    const-wide/16 v1, 0x64

    .line 33
    .line 34
    invoke-virtual {p0, v0, v1, v2}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 35
    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public abstract B()I
.end method

.method public abstract E(Landroid/content/Context;)Ljava/lang/String;
.end method

.method public abstract H(Landroid/content/Context;)I
.end method

.method public abstract T(Landroid/content/Context;)Ljava/lang/String;
.end method

.method public abstract V()Ljava/util/ArrayList;
.end method

.method public abstract W(Ljava/lang/Object;)V
.end method

.method public abstract k0()Z
.end method

.method public abstract l0()Ljava/util/ArrayList;
.end method

.method public abstract n0()Ljava/lang/Object;
.end method

.method public abstract q0(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Lcom/google/android/material/datepicker/c;Lcom/google/android/material/datepicker/x;)Landroid/view/View;
.end method

.method public abstract r0(J)V
.end method
