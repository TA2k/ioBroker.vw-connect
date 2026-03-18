.class public final synthetic Li91/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Ljava/util/List;

.field public final synthetic e:Z

.field public final synthetic f:F


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;ZF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/a1;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-boolean p2, p0, Li91/a1;->e:Z

    .line 7
    .line 8
    iput p3, p0, Li91/a1;->f:F

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    check-cast p1, Lm1/f;

    .line 2
    .line 3
    const-string v0, "$this$LazyColumn"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Li91/c1;

    .line 9
    .line 10
    iget v1, p0, Li91/a1;->f:F

    .line 11
    .line 12
    invoke-direct {v0, v1}, Li91/c1;-><init>(F)V

    .line 13
    .line 14
    .line 15
    const-string v1, "rows"

    .line 16
    .line 17
    iget-object v2, p0, Li91/a1;->d:Ljava/util/List;

    .line 18
    .line 19
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    new-instance v3, Lak/p;

    .line 27
    .line 28
    const/16 v4, 0x19

    .line 29
    .line 30
    invoke-direct {v3, v2, v4}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 31
    .line 32
    .line 33
    new-instance v4, Lf30/f;

    .line 34
    .line 35
    iget-boolean p0, p0, Li91/a1;->e:Z

    .line 36
    .line 37
    invoke-direct {v4, v2, v0, p0, v2}, Lf30/f;-><init>(Ljava/util/List;Li91/c1;ZLjava/util/List;)V

    .line 38
    .line 39
    .line 40
    new-instance p0, Lt2/b;

    .line 41
    .line 42
    const/4 v0, 0x1

    .line 43
    const v2, 0x799532c4

    .line 44
    .line 45
    .line 46
    invoke-direct {p0, v4, v0, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 47
    .line 48
    .line 49
    const/4 v0, 0x0

    .line 50
    invoke-virtual {p1, v1, v0, v3, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 51
    .line 52
    .line 53
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object p0
.end method
