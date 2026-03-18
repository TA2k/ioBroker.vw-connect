.class public final Lf5/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf5/d;
.implements Le5/i;


# instance fields
.field public final a:Lz4/q;

.field public b:I

.field public c:Lh5/h;

.field public d:I

.field public e:I

.field public f:F

.field public g:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lz4/q;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lf5/g;->d:I

    .line 6
    .line 7
    iput v0, p0, Lf5/g;->e:I

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput v0, p0, Lf5/g;->f:F

    .line 11
    .line 12
    iput-object p1, p0, Lf5/g;->a:Lz4/q;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lh5/d;)V
    .locals 1

    .line 1
    instance-of v0, p1, Lh5/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lh5/h;

    .line 6
    .line 7
    iput-object p1, p0, Lf5/g;->c:Lh5/h;

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    const/4 p1, 0x0

    .line 11
    iput-object p1, p0, Lf5/g;->c:Lh5/h;

    .line 12
    .line 13
    return-void
.end method

.method public final apply()V
    .locals 3

    .line 1
    iget-object v0, p0, Lf5/g;->c:Lh5/h;

    .line 2
    .line 3
    iget v1, p0, Lf5/g;->b:I

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lh5/h;->W(I)V

    .line 6
    .line 7
    .line 8
    iget v0, p0, Lf5/g;->d:I

    .line 9
    .line 10
    const/high16 v1, -0x40800000    # -1.0f

    .line 11
    .line 12
    const/4 v2, -0x1

    .line 13
    if-eq v0, v2, :cond_1

    .line 14
    .line 15
    iget-object p0, p0, Lf5/g;->c:Lh5/h;

    .line 16
    .line 17
    if-le v0, v2, :cond_0

    .line 18
    .line 19
    iput v1, p0, Lh5/h;->r0:F

    .line 20
    .line 21
    iput v0, p0, Lh5/h;->s0:I

    .line 22
    .line 23
    iput v2, p0, Lh5/h;->t0:I

    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    iget v0, p0, Lf5/g;->e:I

    .line 31
    .line 32
    if-eq v0, v2, :cond_3

    .line 33
    .line 34
    iget-object p0, p0, Lf5/g;->c:Lh5/h;

    .line 35
    .line 36
    if-le v0, v2, :cond_2

    .line 37
    .line 38
    iput v1, p0, Lh5/h;->r0:F

    .line 39
    .line 40
    iput v2, p0, Lh5/h;->s0:I

    .line 41
    .line 42
    iput v0, p0, Lh5/h;->t0:I

    .line 43
    .line 44
    return-void

    .line 45
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_3
    iget-object v0, p0, Lf5/g;->c:Lh5/h;

    .line 50
    .line 51
    iget p0, p0, Lf5/g;->f:F

    .line 52
    .line 53
    cmpl-float v1, p0, v1

    .line 54
    .line 55
    if-lez v1, :cond_4

    .line 56
    .line 57
    iput p0, v0, Lh5/h;->r0:F

    .line 58
    .line 59
    iput v2, v0, Lh5/h;->s0:I

    .line 60
    .line 61
    iput v2, v0, Lh5/h;->t0:I

    .line 62
    .line 63
    return-void

    .line 64
    :cond_4
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public final b()Lh5/d;
    .locals 1

    .line 1
    iget-object v0, p0, Lf5/g;->c:Lh5/h;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lh5/h;

    .line 6
    .line 7
    invoke-direct {v0}, Lh5/h;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lf5/g;->c:Lh5/h;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lf5/g;->c:Lh5/h;

    .line 13
    .line 14
    return-object p0
.end method

.method public final c()Lf5/d;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final getKey()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lf5/g;->g:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
