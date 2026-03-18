.class public final Lq2/a;
.super Landroidx/collection/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lby0/d;


# instance fields
.field public final g:Lj3/f0;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lj3/f0;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, v0, p2, p3}, Landroidx/collection/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lq2/a;->g:Lj3/f0;

    .line 6
    .line 7
    iput-object p3, p0, Lq2/a;->h:Ljava/lang/Object;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lq2/a;->h:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setValue(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lq2/a;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p1, p0, Lq2/a;->h:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object v1, p0, Lq2/a;->g:Lj3/f0;

    .line 6
    .line 7
    iget-object v1, v1, Lj3/f0;->e:Ljava/util/Iterator;

    .line 8
    .line 9
    check-cast v1, Lq2/d;

    .line 10
    .line 11
    iget-object v2, v1, Lq2/d;->h:Lt2/f;

    .line 12
    .line 13
    iget-object p0, p0, Landroidx/collection/x;->e:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-virtual {v2, p0}, Lt2/f;->containsKey(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_0
    iget-boolean v3, v1, Lq2/c;->f:Z

    .line 23
    .line 24
    if-eqz v3, :cond_3

    .line 25
    .line 26
    if-eqz v3, :cond_2

    .line 27
    .line 28
    iget-object v3, v1, Lq2/c;->g:[Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v3, [Lq2/j;

    .line 31
    .line 32
    iget v4, v1, Lq2/c;->e:I

    .line 33
    .line 34
    aget-object v3, v3, v4

    .line 35
    .line 36
    iget-object v4, v3, Lq2/j;->e:[Ljava/lang/Object;

    .line 37
    .line 38
    iget v3, v3, Lq2/j;->g:I

    .line 39
    .line 40
    aget-object v3, v4, v3

    .line 41
    .line 42
    invoke-virtual {v2, p0, p1}, Lt2/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x0

    .line 46
    if-eqz v3, :cond_1

    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    goto :goto_0

    .line 53
    :cond_1
    move p1, p0

    .line 54
    :goto_0
    iget-object v4, v2, Lt2/f;->e:Lq2/i;

    .line 55
    .line 56
    invoke-virtual {v1, p1, v4, v3, p0}, Lq2/d;->e(ILq2/i;Ljava/lang/Object;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 61
    .line 62
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_3
    invoke-virtual {v2, p0, p1}, Lt2/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    :goto_1
    iget p0, v2, Lt2/f;->g:I

    .line 70
    .line 71
    iput p0, v1, Lq2/d;->k:I

    .line 72
    .line 73
    return-object v0
.end method
