.class public final Lc1/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/t2;


# instance fields
.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public final f:Lc1/b2;

.field public final g:Ll2/j1;

.field public h:Lc1/n1;

.field public i:Z

.field public j:Z

.field public k:J

.field public final synthetic l:Lc1/i0;


# direct methods
.method public constructor <init>(Lc1/i0;Ljava/lang/Object;Ljava/lang/Object;Lc1/b2;Lc1/f0;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc1/g0;->l:Lc1/i0;

    .line 5
    .line 6
    iput-object p2, p0, Lc1/g0;->d:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Lc1/g0;->e:Ljava/lang/Object;

    .line 9
    .line 10
    iput-object p4, p0, Lc1/g0;->f:Lc1/b2;

    .line 11
    .line 12
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lc1/g0;->g:Ll2/j1;

    .line 17
    .line 18
    new-instance v0, Lc1/n1;

    .line 19
    .line 20
    iget-object v3, p0, Lc1/g0;->d:Ljava/lang/Object;

    .line 21
    .line 22
    iget-object v4, p0, Lc1/g0;->e:Ljava/lang/Object;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    move-object v2, p4

    .line 26
    move-object v1, p5

    .line 27
    invoke-direct/range {v0 .. v5}, Lc1/n1;-><init>(Lc1/j;Lc1/b2;Ljava/lang/Object;Ljava/lang/Object;Lc1/p;)V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lc1/g0;->h:Lc1/n1;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/g0;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
