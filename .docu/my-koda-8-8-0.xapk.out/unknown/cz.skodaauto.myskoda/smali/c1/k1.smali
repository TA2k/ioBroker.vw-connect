.class public final synthetic Lc1/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lkotlin/jvm/internal/f0;

.field public final synthetic e:F

.field public final synthetic f:Lc1/f;

.field public final synthetic g:Lc1/k;

.field public final synthetic h:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lkotlin/jvm/internal/f0;FLc1/f;Lc1/k;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc1/k1;->d:Lkotlin/jvm/internal/f0;

    .line 5
    .line 6
    iput p2, p0, Lc1/k1;->e:F

    .line 7
    .line 8
    iput-object p3, p0, Lc1/k1;->f:Lc1/f;

    .line 9
    .line 10
    iput-object p4, p0, Lc1/k1;->g:Lc1/k;

    .line 11
    .line 12
    iput-object p5, p0, Lc1/k1;->h:Lay0/k;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Ljava/lang/Long;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    iget-object p1, p0, Lc1/k1;->d:Lkotlin/jvm/internal/f0;

    .line 8
    .line 9
    iget-object p1, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    move-object v0, p1

    .line 15
    check-cast v0, Lc1/i;

    .line 16
    .line 17
    iget v3, p0, Lc1/k1;->e:F

    .line 18
    .line 19
    iget-object v4, p0, Lc1/k1;->f:Lc1/f;

    .line 20
    .line 21
    iget-object v5, p0, Lc1/k1;->g:Lc1/k;

    .line 22
    .line 23
    iget-object v6, p0, Lc1/k1;->h:Lay0/k;

    .line 24
    .line 25
    invoke-static/range {v0 .. v6}, Lc1/d;->n(Lc1/i;JFLc1/f;Lc1/k;Lay0/k;)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method
