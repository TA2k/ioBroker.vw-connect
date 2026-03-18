.class public final Ltw/b;
.super Ltw/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:I


# direct methods
.method public constructor <init>(ILtw/e;)V
    .locals 1

    .line 1
    invoke-direct {p0, p2}, Ltw/c;-><init>(Ltw/e;)V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ltw/b;->b:I

    .line 5
    .line 6
    if-ltz p1, :cond_0

    .line 7
    .line 8
    const/16 p0, 0x65

    .line 9
    .line 10
    if-ge p1, p0, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    new-instance p2, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v0, "Expected a percentage (0-100), got "

    .line 18
    .line 19
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const/16 p1, 0x2e

    .line 26
    .line 27
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method


# virtual methods
.method public final a(FF)F
    .locals 0

    .line 1
    const/16 p2, 0x64

    .line 2
    .line 3
    int-to-float p2, p2

    .line 4
    div-float/2addr p1, p2

    .line 5
    iget p0, p0, Ltw/b;->b:I

    .line 6
    .line 7
    int-to-float p0, p0

    .line 8
    mul-float/2addr p1, p0

    .line 9
    return p1
.end method
