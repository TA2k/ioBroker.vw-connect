.class public final Lh8/b1;
.super Lt7/p0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Ljava/lang/Object;


# instance fields
.field public final b:J

.field public final c:J

.field public final d:Z

.field public final e:Lt7/x;

.field public final f:Lt7/t;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh8/b1;->g:Ljava/lang/Object;

    .line 7
    .line 8
    new-instance v0, Lo8/s;

    .line 9
    .line 10
    invoke-direct {v0}, Lo8/s;-><init>()V

    .line 11
    .line 12
    .line 13
    sget-object v1, Lhr/h0;->e:Lhr/f0;

    .line 14
    .line 15
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 16
    .line 17
    sget-object v6, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 18
    .line 19
    sget-object v7, Lhr/x0;->h:Lhr/x0;

    .line 20
    .line 21
    new-instance v1, Lt7/s;

    .line 22
    .line 23
    invoke-direct {v1}, Lt7/s;-><init>()V

    .line 24
    .line 25
    .line 26
    sget-object v2, Lt7/v;->a:Lt7/v;

    .line 27
    .line 28
    sget-object v3, Landroid/net/Uri;->EMPTY:Landroid/net/Uri;

    .line 29
    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    new-instance v2, Lt7/u;

    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v5, 0x0

    .line 36
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    invoke-direct/range {v2 .. v9}, Lt7/u;-><init>(Landroid/net/Uri;Ljava/lang/String;Lkp/o9;Ljava/util/List;Lhr/h0;J)V

    .line 42
    .line 43
    .line 44
    :cond_0
    new-instance v2, Lt7/x;

    .line 45
    .line 46
    invoke-virtual {v0}, Lo8/s;->a()Lt7/r;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1}, Lt7/s;->a()Lt7/t;

    .line 50
    .line 51
    .line 52
    sget-object v0, Lt7/a0;->B:Lt7/a0;

    .line 53
    .line 54
    return-void
.end method

.method public constructor <init>(JZZLt7/x;)V
    .locals 0

    .line 1
    if-eqz p4, :cond_0

    .line 2
    .line 3
    iget-object p4, p5, Lt7/x;->c:Lt7/t;

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 p4, 0x0

    .line 7
    :goto_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-wide p1, p0, Lh8/b1;->b:J

    .line 11
    .line 12
    iput-wide p1, p0, Lh8/b1;->c:J

    .line 13
    .line 14
    iput-boolean p3, p0, Lh8/b1;->d:Z

    .line 15
    .line 16
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iput-object p5, p0, Lh8/b1;->e:Lt7/x;

    .line 20
    .line 21
    iput-object p4, p0, Lh8/b1;->f:Lt7/t;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Object;)I
    .locals 0

    .line 1
    sget-object p0, Lh8/b1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, -0x1

    .line 12
    return p0
.end method

.method public final f(ILt7/n0;Z)Lt7/n0;
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {p1, v0}, Lw7/a;->g(II)V

    .line 3
    .line 4
    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    sget-object p1, Lh8/b1;->g:Ljava/lang/Object;

    .line 8
    .line 9
    :goto_0
    move-object v2, p1

    .line 10
    goto :goto_1

    .line 11
    :cond_0
    const/4 p1, 0x0

    .line 12
    goto :goto_0

    .line 13
    :goto_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    sget-object v8, Lt7/b;->c:Lt7/b;

    .line 17
    .line 18
    const/4 v9, 0x0

    .line 19
    const/4 v1, 0x0

    .line 20
    const/4 v3, 0x0

    .line 21
    iget-wide v4, p0, Lh8/b1;->b:J

    .line 22
    .line 23
    const-wide/16 v6, 0x0

    .line 24
    .line 25
    move-object v0, p2

    .line 26
    invoke-virtual/range {v0 .. v9}, Lt7/n0;->h(Ljava/lang/Object;Ljava/lang/Object;IJJLt7/b;Z)V

    .line 27
    .line 28
    .line 29
    return-object v0
.end method

.method public final h()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final l(I)Ljava/lang/Object;
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    invoke-static {p1, p0}, Lw7/a;->g(II)V

    .line 3
    .line 4
    .line 5
    sget-object p0, Lh8/b1;->g:Ljava/lang/Object;

    .line 6
    .line 7
    return-object p0
.end method

.method public final m(ILt7/o0;J)Lt7/o0;
    .locals 9

    .line 1
    const/4 p3, 0x1

    .line 2
    invoke-static {p1, p3}, Lw7/a;->g(II)V

    .line 3
    .line 4
    .line 5
    sget-object p1, Lt7/o0;->p:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v4, p0, Lh8/b1;->f:Lt7/t;

    .line 8
    .line 9
    iget-wide v7, p0, Lh8/b1;->c:J

    .line 10
    .line 11
    iget-object v1, p0, Lh8/b1;->e:Lt7/x;

    .line 12
    .line 13
    iget-boolean v2, p0, Lh8/b1;->d:Z

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    const-wide/16 v5, 0x0

    .line 17
    .line 18
    move-object v0, p2

    .line 19
    invoke-virtual/range {v0 .. v8}, Lt7/o0;->b(Lt7/x;ZZLt7/t;JJ)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final o()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
