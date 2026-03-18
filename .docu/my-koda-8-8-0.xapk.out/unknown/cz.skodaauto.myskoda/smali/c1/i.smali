.class public final Lc1/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lc1/b2;

.field public final b:Ljava/lang/Object;

.field public final c:J

.field public final d:Lay0/a;

.field public final e:Ll2/j1;

.field public f:Lc1/p;

.field public g:J

.field public h:J

.field public final i:Ll2/j1;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Lc1/b2;Lc1/p;JLjava/lang/Object;JLay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lc1/i;->a:Lc1/b2;

    .line 5
    .line 6
    iput-object p6, p0, Lc1/i;->b:Ljava/lang/Object;

    .line 7
    .line 8
    iput-wide p7, p0, Lc1/i;->c:J

    .line 9
    .line 10
    iput-object p9, p0, Lc1/i;->d:Lay0/a;

    .line 11
    .line 12
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lc1/i;->e:Ll2/j1;

    .line 17
    .line 18
    invoke-static {p3}, Lc1/d;->l(Lc1/p;)Lc1/p;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lc1/i;->f:Lc1/p;

    .line 23
    .line 24
    iput-wide p4, p0, Lc1/i;->g:J

    .line 25
    .line 26
    const-wide/high16 p1, -0x8000000000000000L

    .line 27
    .line 28
    iput-wide p1, p0, Lc1/i;->h:J

    .line 29
    .line 30
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 31
    .line 32
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lc1/i;->i:Ll2/j1;

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/i;->i:Ll2/j1;

    .line 2
    .line 3
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lc1/i;->d:Lay0/a;

    .line 9
    .line 10
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final b()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lc1/i;->a:Lc1/b2;

    .line 2
    .line 3
    iget-object v0, v0, Lc1/b2;->b:Lay0/k;

    .line 4
    .line 5
    iget-object p0, p0, Lc1/i;->f:Lc1/p;

    .line 6
    .line 7
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
