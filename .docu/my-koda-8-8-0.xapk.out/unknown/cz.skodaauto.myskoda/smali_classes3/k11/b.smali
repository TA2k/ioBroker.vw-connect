.class public final Lk11/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/CharSequence;

.field public final b:Lj11/w;


# direct methods
.method public constructor <init>(Ljava/lang/CharSequence;Lj11/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iput-object p1, p0, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 7
    .line 8
    iput-object p2, p0, Lk11/b;->b:Lj11/w;

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 12
    .line 13
    const-string p1, "content must not be null"

    .line 14
    .line 15
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method


# virtual methods
.method public final a(II)Lk11/b;
    .locals 2

    .line 1
    iget-object v0, p0, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lk11/b;->b:Lj11/w;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget v1, p0, Lj11/w;->b:I

    .line 12
    .line 13
    add-int/2addr v1, p1

    .line 14
    sub-int/2addr p2, p1

    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    iget p0, p0, Lj11/w;->a:I

    .line 18
    .line 19
    new-instance p1, Lj11/w;

    .line 20
    .line 21
    invoke-direct {p1, p0, v1, p2}, Lj11/w;-><init>(III)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p1, 0x0

    .line 26
    :goto_0
    new-instance p0, Lk11/b;

    .line 27
    .line 28
    invoke-direct {p0, v0, p1}, Lk11/b;-><init>(Ljava/lang/CharSequence;Lj11/w;)V

    .line 29
    .line 30
    .line 31
    return-object p0
.end method
