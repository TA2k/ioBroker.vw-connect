.class public final Lq8/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lq8/a;


# instance fields
.field public final a:I

.field public final b:I

.field public final c:I

.field public final d:I

.field public final e:I

.field public final f:I


# direct methods
.method public constructor <init>(IIIIII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lq8/d;->a:I

    .line 5
    .line 6
    iput p2, p0, Lq8/d;->b:I

    .line 7
    .line 8
    iput p3, p0, Lq8/d;->c:I

    .line 9
    .line 10
    iput p4, p0, Lq8/d;->d:I

    .line 11
    .line 12
    iput p5, p0, Lq8/d;->e:I

    .line 13
    .line 14
    iput p6, p0, Lq8/d;->f:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 2

    .line 1
    const v0, 0x73646976

    .line 2
    .line 3
    .line 4
    iget p0, p0, Lq8/d;->a:I

    .line 5
    .line 6
    if-eq p0, v0, :cond_2

    .line 7
    .line 8
    const v0, 0x73647561

    .line 9
    .line 10
    .line 11
    if-eq p0, v0, :cond_1

    .line 12
    .line 13
    const v0, 0x73747874

    .line 14
    .line 15
    .line 16
    if-eq p0, v0, :cond_0

    .line 17
    .line 18
    new-instance v0, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v1, "Found unsupported streamType fourCC: "

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    const-string v0, "AviStreamHeaderChunk"

    .line 37
    .line 38
    invoke-static {v0, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const/4 p0, -0x1

    .line 42
    return p0

    .line 43
    :cond_0
    const/4 p0, 0x3

    .line 44
    return p0

    .line 45
    :cond_1
    const/4 p0, 0x1

    .line 46
    return p0

    .line 47
    :cond_2
    const/4 p0, 0x2

    .line 48
    return p0
.end method

.method public final getType()I
    .locals 0

    .line 1
    const p0, 0x68727473

    .line 2
    .line 3
    .line 4
    return p0
.end method
