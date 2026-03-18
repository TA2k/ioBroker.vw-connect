.class public final Lt1/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lt1/p0;

.field public final b:Le2/w0;

.field public final c:Ll4/v;

.field public final d:Z

.field public final e:Z

.field public final f:Le2/c1;

.field public final g:Ll4/p;

.field public final h:Lt1/n1;

.field public final i:Lt1/a0;

.field public final j:Lt1/h0;

.field public final k:Lay0/k;

.field public final l:I


# direct methods
.method public constructor <init>(Lt1/p0;Le2/w0;Ll4/v;ZZLe2/c1;Ll4/p;Lt1/n1;Lt1/a0;Lay0/k;I)V
    .locals 1

    .line 1
    sget-object v0, Lt1/l0;->a:Lt1/h0;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lt1/a1;->a:Lt1/p0;

    .line 7
    .line 8
    iput-object p2, p0, Lt1/a1;->b:Le2/w0;

    .line 9
    .line 10
    iput-object p3, p0, Lt1/a1;->c:Ll4/v;

    .line 11
    .line 12
    iput-boolean p4, p0, Lt1/a1;->d:Z

    .line 13
    .line 14
    iput-boolean p5, p0, Lt1/a1;->e:Z

    .line 15
    .line 16
    iput-object p6, p0, Lt1/a1;->f:Le2/c1;

    .line 17
    .line 18
    iput-object p7, p0, Lt1/a1;->g:Ll4/p;

    .line 19
    .line 20
    iput-object p8, p0, Lt1/a1;->h:Lt1/n1;

    .line 21
    .line 22
    iput-object p9, p0, Lt1/a1;->i:Lt1/a0;

    .line 23
    .line 24
    iput-object v0, p0, Lt1/a1;->j:Lt1/h0;

    .line 25
    .line 26
    iput-object p10, p0, Lt1/a1;->k:Lay0/k;

    .line 27
    .line 28
    iput p11, p0, Lt1/a1;->l:I

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/List;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lt1/a1;->a:Lt1/p0;

    .line 2
    .line 3
    iget-object v0, v0, Lt1/p0;->d:Lb81/a;

    .line 4
    .line 5
    check-cast p1, Ljava/util/Collection;

    .line 6
    .line 7
    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    new-instance v1, Ll4/h;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-virtual {p1, v2, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, p1}, Lb81/a;->k(Ljava/util/List;)Ll4/v;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iget-object p0, p0, Lt1/a1;->k:Lay0/k;

    .line 25
    .line 26
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    return-void
.end method
