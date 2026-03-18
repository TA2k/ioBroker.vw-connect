.class public final Lx4/s;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:Lkotlin/jvm/internal/e0;

.field public final synthetic g:Lx4/t;

.field public final synthetic h:Lt4/k;

.field public final synthetic i:J

.field public final synthetic j:J


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/e0;Lx4/t;Lt4/k;JJ)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx4/s;->f:Lkotlin/jvm/internal/e0;

    .line 2
    .line 3
    iput-object p2, p0, Lx4/s;->g:Lx4/t;

    .line 4
    .line 5
    iput-object p3, p0, Lx4/s;->h:Lt4/k;

    .line 6
    .line 7
    iput-wide p4, p0, Lx4/s;->i:J

    .line 8
    .line 9
    iput-wide p6, p0, Lx4/s;->j:J

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Lx4/s;->g:Lx4/t;

    .line 2
    .line 3
    invoke-virtual {v0}, Lx4/t;->getPositionProvider()Lx4/v;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v0}, Lx4/t;->getParentLayoutDirection()Lt4/m;

    .line 8
    .line 9
    .line 10
    move-result-object v5

    .line 11
    iget-wide v6, p0, Lx4/s;->j:J

    .line 12
    .line 13
    iget-object v2, p0, Lx4/s;->h:Lt4/k;

    .line 14
    .line 15
    iget-wide v3, p0, Lx4/s;->i:J

    .line 16
    .line 17
    invoke-interface/range {v1 .. v7}, Lx4/v;->F(Lt4/k;JLt4/m;J)J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    iget-object p0, p0, Lx4/s;->f:Lkotlin/jvm/internal/e0;

    .line 22
    .line 23
    iput-wide v0, p0, Lkotlin/jvm/internal/e0;->d:J

    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method
