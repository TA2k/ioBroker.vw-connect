.class public final Li9/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public b:I

.field public c:I

.field public d:J

.field public final e:Z

.field public final f:Lw7/p;

.field public final g:Lw7/p;

.field public h:I

.field public i:I


# direct methods
.method public constructor <init>(Lw7/p;Lw7/p;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li9/b;->g:Lw7/p;

    .line 5
    .line 6
    iput-object p2, p0, Li9/b;->f:Lw7/p;

    .line 7
    .line 8
    iput-boolean p3, p0, Li9/b;->e:Z

    .line 9
    .line 10
    const/16 p3, 0xc

    .line 11
    .line 12
    invoke-virtual {p2, p3}, Lw7/p;->I(I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p2}, Lw7/p;->A()I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iput p2, p0, Li9/b;->a:I

    .line 20
    .line 21
    invoke-virtual {p1, p3}, Lw7/p;->I(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Lw7/p;->A()I

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    iput p2, p0, Li9/b;->i:I

    .line 29
    .line 30
    invoke-virtual {p1}, Lw7/p;->j()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    const/4 p2, 0x1

    .line 35
    if-ne p1, p2, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 p2, 0x0

    .line 39
    :goto_0
    const-string p1, "first_chunk must be 1"

    .line 40
    .line 41
    invoke-static {p1, p2}, Lo8/b;->c(Ljava/lang/String;Z)V

    .line 42
    .line 43
    .line 44
    const/4 p1, -0x1

    .line 45
    iput p1, p0, Li9/b;->b:I

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 4

    .line 1
    iget v0, p0, Li9/b;->b:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    add-int/2addr v0, v1

    .line 5
    iput v0, p0, Li9/b;->b:I

    .line 6
    .line 7
    iget v2, p0, Li9/b;->a:I

    .line 8
    .line 9
    if-ne v0, v2, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    iget-boolean v0, p0, Li9/b;->e:Z

    .line 14
    .line 15
    iget-object v2, p0, Li9/b;->f:Lw7/p;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {v2}, Lw7/p;->B()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 25
    .line 26
    .line 27
    move-result-wide v2

    .line 28
    :goto_0
    iput-wide v2, p0, Li9/b;->d:J

    .line 29
    .line 30
    iget v0, p0, Li9/b;->b:I

    .line 31
    .line 32
    iget v2, p0, Li9/b;->h:I

    .line 33
    .line 34
    if-ne v0, v2, :cond_3

    .line 35
    .line 36
    iget-object v0, p0, Li9/b;->g:Lw7/p;

    .line 37
    .line 38
    invoke-virtual {v0}, Lw7/p;->A()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    iput v2, p0, Li9/b;->c:I

    .line 43
    .line 44
    const/4 v2, 0x4

    .line 45
    invoke-virtual {v0, v2}, Lw7/p;->J(I)V

    .line 46
    .line 47
    .line 48
    iget v2, p0, Li9/b;->i:I

    .line 49
    .line 50
    sub-int/2addr v2, v1

    .line 51
    iput v2, p0, Li9/b;->i:I

    .line 52
    .line 53
    if-lez v2, :cond_2

    .line 54
    .line 55
    invoke-virtual {v0}, Lw7/p;->A()I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    sub-int/2addr v0, v1

    .line 60
    goto :goto_1

    .line 61
    :cond_2
    const/4 v0, -0x1

    .line 62
    :goto_1
    iput v0, p0, Li9/b;->h:I

    .line 63
    .line 64
    :cond_3
    return v1
.end method
