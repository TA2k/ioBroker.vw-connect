.class public final Ll9/c;
.super Lz7/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll9/d;


# instance fields
.field public h:Ll9/d;

.field public i:J

.field public final synthetic j:I

.field public k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Ll9/c;->j:I

    invoke-direct {p0}, Lkq/d;-><init>()V

    return-void
.end method

.method public constructor <init>(Li8/b;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ll9/c;->j:I

    .line 2
    invoke-direct {p0}, Lkq/d;-><init>()V

    .line 3
    iput-object p1, p0, Ll9/c;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final e(J)I
    .locals 3

    .line 1
    iget-object v0, p0, Ll9/c;->h:Ll9/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-wide v1, p0, Ll9/c;->i:J

    .line 7
    .line 8
    sub-long/2addr p1, v1

    .line 9
    invoke-interface {v0, p1, p2}, Ll9/d;->e(J)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final f(J)Ljava/util/List;
    .locals 3

    .line 1
    iget-object v0, p0, Ll9/c;->h:Ll9/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-wide v1, p0, Ll9/c;->i:J

    .line 7
    .line 8
    sub-long/2addr p1, v1

    .line 9
    invoke-interface {v0, p1, p2}, Ll9/d;->f(J)Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final i(I)J
    .locals 2

    .line 1
    iget-object v0, p0, Ll9/c;->h:Ll9/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-interface {v0, p1}, Ll9/d;->i(I)J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    iget-wide p0, p0, Ll9/c;->i:J

    .line 11
    .line 12
    add-long/2addr v0, p0

    .line 13
    return-wide v0
.end method

.method public final k()I
    .locals 0

    .line 1
    iget-object p0, p0, Ll9/c;->h:Ll9/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ll9/d;->k()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final m()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lkq/d;->e:I

    .line 3
    .line 4
    const-wide/16 v1, 0x0

    .line 5
    .line 6
    iput-wide v1, p0, Lz7/f;->f:J

    .line 7
    .line 8
    iput-boolean v0, p0, Lz7/f;->g:Z

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Ll9/c;->h:Ll9/d;

    .line 12
    .line 13
    return-void
.end method

.method public final n()V
    .locals 1

    .line 1
    iget v0, p0, Ll9/c;->j:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll9/c;->k:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lgr/k;

    .line 9
    .line 10
    iget-object v0, v0, Lgr/k;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lm9/i;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Ll9/c;->m()V

    .line 18
    .line 19
    .line 20
    iget-object v0, v0, Lm9/i;->b:Ljava/util/ArrayDeque;

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_0
    iget-object v0, p0, Ll9/c;->k:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Li8/b;

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Lz7/g;->n(Lz7/f;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
