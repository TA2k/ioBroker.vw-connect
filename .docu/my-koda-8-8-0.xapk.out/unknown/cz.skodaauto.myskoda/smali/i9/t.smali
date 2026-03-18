.class public final Li9/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Li9/q;

.field public final b:I

.field public final c:[J

.field public final d:[I

.field public final e:I

.field public final f:[J

.field public final g:[I

.field public final h:J


# direct methods
.method public constructor <init>(Li9/q;[J[II[J[IJ)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    array-length v0, p3

    .line 5
    array-length v1, p5

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x1

    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    move v0, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v0, v2

    .line 13
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 14
    .line 15
    .line 16
    array-length v0, p2

    .line 17
    array-length v1, p5

    .line 18
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    move v0, v3

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    move v0, v2

    .line 23
    :goto_1
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 24
    .line 25
    .line 26
    array-length v0, p6

    .line 27
    array-length v1, p5

    .line 28
    if-ne v0, v1, :cond_2

    .line 29
    .line 30
    move v2, v3

    .line 31
    :cond_2
    invoke-static {v2}, Lw7/a;->c(Z)V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Li9/t;->a:Li9/q;

    .line 35
    .line 36
    iput-object p2, p0, Li9/t;->c:[J

    .line 37
    .line 38
    iput-object p3, p0, Li9/t;->d:[I

    .line 39
    .line 40
    iput p4, p0, Li9/t;->e:I

    .line 41
    .line 42
    iput-object p5, p0, Li9/t;->f:[J

    .line 43
    .line 44
    iput-object p6, p0, Li9/t;->g:[I

    .line 45
    .line 46
    iput-wide p7, p0, Li9/t;->h:J

    .line 47
    .line 48
    array-length p1, p2

    .line 49
    iput p1, p0, Li9/t;->b:I

    .line 50
    .line 51
    array-length p0, p6

    .line 52
    if-lez p0, :cond_3

    .line 53
    .line 54
    array-length p0, p6

    .line 55
    sub-int/2addr p0, v3

    .line 56
    aget p1, p6, p0

    .line 57
    .line 58
    const/high16 p2, 0x20000000

    .line 59
    .line 60
    or-int/2addr p1, p2

    .line 61
    aput p1, p6, p0

    .line 62
    .line 63
    :cond_3
    return-void
.end method


# virtual methods
.method public final a(J)I
    .locals 2

    .line 1
    iget-object v0, p0, Li9/t;->f:[J

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-static {v0, p1, p2, v1}, Lw7/w;->a([JJZ)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    :goto_0
    array-length p2, v0

    .line 9
    if-ge p1, p2, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Li9/t;->g:[I

    .line 12
    .line 13
    aget p2, p2, p1

    .line 14
    .line 15
    and-int/2addr p2, v1

    .line 16
    if-eqz p2, :cond_0

    .line 17
    .line 18
    return p1

    .line 19
    :cond_0
    add-int/lit8 p1, p1, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    const/4 p0, -0x1

    .line 23
    return p0
.end method
