.class public final Lh8/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/h0;
.implements Ld8/g;


# instance fields
.field public final d:Ljava/lang/Object;

.field public e:Ld8/f;

.field public f:Ld8/f;

.field public final synthetic g:Lh8/k;


# direct methods
.method public constructor <init>(Lh8/k;Ljava/lang/Object;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/i;->g:Lh8/k;

    .line 5
    .line 6
    iget-object v0, p1, Lh8/a;->c:Ld8/f;

    .line 7
    .line 8
    new-instance v1, Ld8/f;

    .line 9
    .line 10
    iget-object v0, v0, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v1, v0, v2, v3}, Ld8/f;-><init>(Ljava/util/concurrent/CopyOnWriteArrayList;ILh8/b0;)V

    .line 15
    .line 16
    .line 17
    iput-object v1, p0, Lh8/i;->e:Ld8/f;

    .line 18
    .line 19
    iget-object p1, p1, Lh8/a;->d:Ld8/f;

    .line 20
    .line 21
    new-instance v0, Ld8/f;

    .line 22
    .line 23
    iget-object p1, p1, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 24
    .line 25
    invoke-direct {v0, p1, v2, v3}, Ld8/f;-><init>(Ljava/util/concurrent/CopyOnWriteArrayList;ILh8/b0;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lh8/i;->f:Ld8/f;

    .line 29
    .line 30
    iput-object p2, p0, Lh8/i;->d:Ljava/lang/Object;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final F(ILh8/b0;Lh8/s;Lh8/x;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lh8/i;->a(ILh8/b0;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lh8/i;->e:Ld8/f;

    .line 8
    .line 9
    invoke-virtual {p0, p4, p2}, Lh8/i;->b(Lh8/x;Lh8/b0;)Lh8/x;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    new-instance p2, Lh8/e0;

    .line 17
    .line 18
    const/4 p4, 0x1

    .line 19
    invoke-direct {p2, p1, p3, p0, p4}, Lh8/e0;-><init>(Ld8/f;Lh8/s;Lh8/x;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, p2}, Ld8/f;->a(Lw7/f;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public final a(ILh8/b0;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lh8/i;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iget-object v1, p0, Lh8/i;->g:Lh8/k;

    .line 4
    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1, v0, p2}, Lh8/k;->s(Ljava/lang/Object;Lh8/b0;)Lh8/b0;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    if-nez p2, :cond_1

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p2, 0x0

    .line 16
    :cond_1
    invoke-virtual {v1, p1, v0}, Lh8/k;->u(ILjava/lang/Object;)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    iget-object v0, p0, Lh8/i;->e:Ld8/f;

    .line 21
    .line 22
    iget v2, v0, Ld8/f;->a:I

    .line 23
    .line 24
    if-ne v2, p1, :cond_2

    .line 25
    .line 26
    iget-object v0, v0, Ld8/f;->b:Lh8/b0;

    .line 27
    .line 28
    invoke-static {v0, p2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_3

    .line 33
    .line 34
    :cond_2
    iget-object v0, v1, Lh8/a;->c:Ld8/f;

    .line 35
    .line 36
    new-instance v2, Ld8/f;

    .line 37
    .line 38
    iget-object v0, v0, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 39
    .line 40
    invoke-direct {v2, v0, p1, p2}, Ld8/f;-><init>(Ljava/util/concurrent/CopyOnWriteArrayList;ILh8/b0;)V

    .line 41
    .line 42
    .line 43
    iput-object v2, p0, Lh8/i;->e:Ld8/f;

    .line 44
    .line 45
    :cond_3
    iget-object v0, p0, Lh8/i;->f:Ld8/f;

    .line 46
    .line 47
    iget v2, v0, Ld8/f;->a:I

    .line 48
    .line 49
    if-ne v2, p1, :cond_4

    .line 50
    .line 51
    iget-object v0, v0, Ld8/f;->b:Lh8/b0;

    .line 52
    .line 53
    invoke-static {v0, p2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-nez v0, :cond_5

    .line 58
    .line 59
    :cond_4
    iget-object v0, v1, Lh8/a;->d:Ld8/f;

    .line 60
    .line 61
    new-instance v1, Ld8/f;

    .line 62
    .line 63
    iget-object v0, v0, Ld8/f;->c:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 64
    .line 65
    invoke-direct {v1, v0, p1, p2}, Ld8/f;-><init>(Ljava/util/concurrent/CopyOnWriteArrayList;ILh8/b0;)V

    .line 66
    .line 67
    .line 68
    iput-object v1, p0, Lh8/i;->f:Ld8/f;

    .line 69
    .line 70
    :cond_5
    const/4 p0, 0x1

    .line 71
    return p0
.end method

.method public final b(Lh8/x;Lh8/b0;)Lh8/x;
    .locals 9

    .line 1
    iget-wide v0, p1, Lh8/x;->c:J

    .line 2
    .line 3
    iget-object p2, p0, Lh8/i;->g:Lh8/k;

    .line 4
    .line 5
    iget-object p0, p0, Lh8/i;->d:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {p2, v0, v1, p0}, Lh8/k;->t(JLjava/lang/Object;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v5

    .line 11
    iget-wide v2, p1, Lh8/x;->d:J

    .line 12
    .line 13
    invoke-virtual {p2, v2, v3, p0}, Lh8/k;->t(JLjava/lang/Object;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v7

    .line 17
    cmp-long p0, v5, v0

    .line 18
    .line 19
    if-nez p0, :cond_0

    .line 20
    .line 21
    cmp-long p0, v7, v2

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    return-object p1

    .line 26
    :cond_0
    new-instance v2, Lh8/x;

    .line 27
    .line 28
    iget v3, p1, Lh8/x;->a:I

    .line 29
    .line 30
    iget-object v4, p1, Lh8/x;->b:Lt7/o;

    .line 31
    .line 32
    invoke-direct/range {v2 .. v8}, Lh8/x;-><init>(ILt7/o;JJ)V

    .line 33
    .line 34
    .line 35
    return-object v2
.end method

.method public final c(ILh8/b0;Lh8/s;Lh8/x;I)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lh8/i;->a(ILh8/b0;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lh8/i;->e:Ld8/f;

    .line 8
    .line 9
    invoke-virtual {p0, p4, p2}, Lh8/i;->b(Lh8/x;Lh8/b0;)Lh8/x;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    new-instance p2, Lh8/d0;

    .line 17
    .line 18
    invoke-direct {p2, p1, p3, p0, p5}, Lh8/d0;-><init>(Ld8/f;Lh8/s;Lh8/x;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1, p2}, Ld8/f;->a(Lw7/f;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public final d(ILh8/b0;Lh8/x;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lh8/i;->a(ILh8/b0;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lh8/i;->e:Ld8/f;

    .line 8
    .line 9
    invoke-virtual {p0, p3, p2}, Lh8/i;->b(Lh8/x;Lh8/b0;)Lh8/x;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    new-instance p2, La0/h;

    .line 17
    .line 18
    const/16 p3, 0x11

    .line 19
    .line 20
    invoke-direct {p2, p3, p1, p0}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, p2}, Ld8/f;->a(Lw7/f;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method public final e(ILh8/b0;Lh8/s;Lh8/x;Ljava/io/IOException;Z)V
    .locals 6

    .line 1
    invoke-virtual {p0, p1, p2}, Lh8/i;->a(ILh8/b0;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lh8/i;->e:Ld8/f;

    .line 8
    .line 9
    invoke-virtual {p0, p4, p2}, Lh8/i;->b(Lh8/x;Lh8/b0;)Lh8/x;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    new-instance v0, Lh8/f0;

    .line 17
    .line 18
    move-object v2, p3

    .line 19
    move-object v4, p5

    .line 20
    move v5, p6

    .line 21
    invoke-direct/range {v0 .. v5}, Lh8/f0;-><init>(Ld8/f;Lh8/s;Lh8/x;Ljava/io/IOException;Z)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, v0}, Ld8/f;->a(Lw7/f;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final j(ILh8/b0;Lh8/s;Lh8/x;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lh8/i;->a(ILh8/b0;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lh8/i;->e:Ld8/f;

    .line 8
    .line 9
    invoke-virtual {p0, p4, p2}, Lh8/i;->b(Lh8/x;Lh8/b0;)Lh8/x;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    new-instance p2, Lh8/e0;

    .line 17
    .line 18
    const/4 p4, 0x0

    .line 19
    invoke-direct {p2, p1, p3, p0, p4}, Lh8/e0;-><init>(Ld8/f;Lh8/s;Lh8/x;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, p2}, Ld8/f;->a(Lw7/f;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method
