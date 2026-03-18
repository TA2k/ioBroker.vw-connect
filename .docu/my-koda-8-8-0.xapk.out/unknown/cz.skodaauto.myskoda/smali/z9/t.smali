.class public final Lz9/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final d:Lz9/u;

.field public final e:Landroid/os/Bundle;

.field public final f:Z

.field public final g:I

.field public final h:Z


# direct methods
.method public constructor <init>(Lz9/u;Landroid/os/Bundle;ZIZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz9/t;->d:Lz9/u;

    .line 5
    .line 6
    iput-object p2, p0, Lz9/t;->e:Landroid/os/Bundle;

    .line 7
    .line 8
    iput-boolean p3, p0, Lz9/t;->f:Z

    .line 9
    .line 10
    iput p4, p0, Lz9/t;->g:I

    .line 11
    .line 12
    iput-boolean p5, p0, Lz9/t;->h:Z

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lz9/t;)I
    .locals 4

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p1, Lz9/t;->h:Z

    .line 7
    .line 8
    iget-boolean v1, p1, Lz9/t;->f:Z

    .line 9
    .line 10
    iget-object v2, p1, Lz9/t;->e:Landroid/os/Bundle;

    .line 11
    .line 12
    iget-boolean v3, p0, Lz9/t;->f:Z

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    if-nez v3, :cond_1

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    iget v1, p0, Lz9/t;->g:I

    .line 25
    .line 26
    iget p1, p1, Lz9/t;->g:I

    .line 27
    .line 28
    sub-int/2addr v1, p1

    .line 29
    if-lez v1, :cond_2

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    if-gez v1, :cond_3

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_3
    iget-object p1, p0, Lz9/t;->e:Landroid/os/Bundle;

    .line 36
    .line 37
    if-eqz p1, :cond_4

    .line 38
    .line 39
    if-nez v2, :cond_4

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_4
    if-nez p1, :cond_5

    .line 43
    .line 44
    if-eqz v2, :cond_5

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_5
    if-eqz p1, :cond_7

    .line 48
    .line 49
    invoke-virtual {p1}, Landroid/os/BaseBundle;->size()I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v2}, Landroid/os/BaseBundle;->size()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    sub-int/2addr p1, v1

    .line 61
    if-lez p1, :cond_6

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_6
    if-gez p1, :cond_7

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_7
    iget-boolean p0, p0, Lz9/t;->h:Z

    .line 68
    .line 69
    if-eqz p0, :cond_8

    .line 70
    .line 71
    if-nez v0, :cond_8

    .line 72
    .line 73
    :goto_0
    const/4 p0, 0x1

    .line 74
    return p0

    .line 75
    :cond_8
    if-nez p0, :cond_9

    .line 76
    .line 77
    if-eqz v0, :cond_9

    .line 78
    .line 79
    :goto_1
    const/4 p0, -0x1

    .line 80
    return p0

    .line 81
    :cond_9
    const/4 p0, 0x0

    .line 82
    return p0
.end method

.method public final bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lz9/t;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lz9/t;->a(Lz9/t;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
