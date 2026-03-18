.class public final Lty0/d;
.super Lr2/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lty0/c;

.field public i:Ljava/lang/Object;

.field public j:Z

.field public k:I


# direct methods
.method public constructor <init>(Lty0/c;)V
    .locals 3

    .line 1
    iget-object v0, p1, Lty0/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget-object v1, p1, Lty0/c;->g:Lsy0/d;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {p0, v0, v1, v2}, Lr2/c;-><init>(Ljava/lang/Object;Ljava/util/Map;I)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lty0/d;->h:Lty0/c;

    .line 10
    .line 11
    iget p1, v1, Lsy0/d;->h:I

    .line 12
    .line 13
    iput p1, p0, Lty0/d;->k:I

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lty0/d;->h:Lty0/c;

    .line 2
    .line 3
    iget-object v0, v0, Lty0/c;->g:Lsy0/d;

    .line 4
    .line 5
    iget v0, v0, Lsy0/d;->h:I

    .line 6
    .line 7
    iget v1, p0, Lty0/d;->k:I

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    invoke-super {p0}, Lr2/c;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lty0/d;->i:Ljava/lang/Object;

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    iput-boolean v1, p0, Lty0/d;->j:Z

    .line 19
    .line 20
    return-object v0

    .line 21
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public final remove()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lty0/d;->j:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lty0/d;->i:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v1, p0, Lty0/d;->h:Lty0/c;

    .line 8
    .line 9
    invoke-static {v1}, Lkotlin/jvm/internal/j0;->a(Ljava/lang/Object;)Ljava/util/Collection;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-interface {v2, v0}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iput-object v0, p0, Lty0/d;->i:Ljava/lang/Object;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    iput-boolean v0, p0, Lty0/d;->j:Z

    .line 21
    .line 22
    iget-object v0, v1, Lty0/c;->g:Lsy0/d;

    .line 23
    .line 24
    iget v0, v0, Lsy0/d;->h:I

    .line 25
    .line 26
    iput v0, p0, Lty0/d;->k:I

    .line 27
    .line 28
    iget v0, p0, Lr2/c;->g:I

    .line 29
    .line 30
    add-int/lit8 v0, v0, -0x1

    .line 31
    .line 32
    iput v0, p0, Lr2/c;->g:I

    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0
.end method
