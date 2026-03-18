.class public abstract Landroidx/lifecycle/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Landroidx/lifecycle/j0;

.field public e:Z

.field public f:I

.field public final synthetic g:Landroidx/lifecycle/g0;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/g0;Landroidx/lifecycle/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/lifecycle/f0;->g:Landroidx/lifecycle/g0;

    .line 5
    .line 6
    const/4 p1, -0x1

    .line 7
    iput p1, p0, Landroidx/lifecycle/f0;->f:I

    .line 8
    .line 9
    iput-object p2, p0, Landroidx/lifecycle/f0;->d:Landroidx/lifecycle/j0;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Z)V
    .locals 5

    .line 1
    iget-boolean v0, p0, Landroidx/lifecycle/f0;->e:Z

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    goto :goto_6

    .line 6
    :cond_0
    iput-boolean p1, p0, Landroidx/lifecycle/f0;->e:Z

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    if-eqz p1, :cond_1

    .line 10
    .line 11
    move p1, v0

    .line 12
    goto :goto_0

    .line 13
    :cond_1
    const/4 p1, -0x1

    .line 14
    :goto_0
    iget-object v1, p0, Landroidx/lifecycle/f0;->g:Landroidx/lifecycle/g0;

    .line 15
    .line 16
    iget v2, v1, Landroidx/lifecycle/g0;->c:I

    .line 17
    .line 18
    add-int/2addr p1, v2

    .line 19
    iput p1, v1, Landroidx/lifecycle/g0;->c:I

    .line 20
    .line 21
    iget-boolean p1, v1, Landroidx/lifecycle/g0;->d:Z

    .line 22
    .line 23
    if-eqz p1, :cond_2

    .line 24
    .line 25
    goto :goto_5

    .line 26
    :cond_2
    iput-boolean v0, v1, Landroidx/lifecycle/g0;->d:Z

    .line 27
    .line 28
    :goto_1
    const/4 p1, 0x0

    .line 29
    :try_start_0
    iget v3, v1, Landroidx/lifecycle/g0;->c:I

    .line 30
    .line 31
    if-eq v2, v3, :cond_7

    .line 32
    .line 33
    if-nez v2, :cond_3

    .line 34
    .line 35
    if-lez v3, :cond_3

    .line 36
    .line 37
    move v4, v0

    .line 38
    goto :goto_2

    .line 39
    :cond_3
    move v4, p1

    .line 40
    :goto_2
    if-lez v2, :cond_4

    .line 41
    .line 42
    if-nez v3, :cond_4

    .line 43
    .line 44
    move v2, v0

    .line 45
    goto :goto_3

    .line 46
    :cond_4
    move v2, p1

    .line 47
    :goto_3
    if-eqz v4, :cond_5

    .line 48
    .line 49
    invoke-virtual {v1}, Landroidx/lifecycle/g0;->g()V

    .line 50
    .line 51
    .line 52
    goto :goto_4

    .line 53
    :catchall_0
    move-exception p0

    .line 54
    goto :goto_7

    .line 55
    :cond_5
    if-eqz v2, :cond_6

    .line 56
    .line 57
    invoke-virtual {v1}, Landroidx/lifecycle/g0;->h()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    .line 59
    .line 60
    :cond_6
    :goto_4
    move v2, v3

    .line 61
    goto :goto_1

    .line 62
    :cond_7
    iput-boolean p1, v1, Landroidx/lifecycle/g0;->d:Z

    .line 63
    .line 64
    :goto_5
    iget-boolean p1, p0, Landroidx/lifecycle/f0;->e:Z

    .line 65
    .line 66
    if-eqz p1, :cond_8

    .line 67
    .line 68
    invoke-virtual {v1, p0}, Landroidx/lifecycle/g0;->c(Landroidx/lifecycle/f0;)V

    .line 69
    .line 70
    .line 71
    :cond_8
    :goto_6
    return-void

    .line 72
    :goto_7
    iput-boolean p1, v1, Landroidx/lifecycle/g0;->d:Z

    .line 73
    .line 74
    throw p0
.end method

.method public b()V
    .locals 0

    .line 1
    return-void
.end method

.method public c(Landroidx/fragment/app/j0;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public abstract d()Z
.end method
