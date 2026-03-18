.class public final Ljn/m;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lx2/s;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:J

.field public final synthetic k:Ljava/util/List;

.field public final synthetic l:Lg4/p0;

.field public final synthetic m:I


# direct methods
.method public constructor <init>(Lx2/s;Lay0/k;Ljava/lang/Integer;Lay0/k;JLjava/util/List;Lg4/p0;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Ljn/m;->f:Lx2/s;

    .line 2
    .line 3
    iput-object p2, p0, Ljn/m;->g:Lay0/k;

    .line 4
    .line 5
    iput-object p3, p0, Ljn/m;->h:Ljava/lang/Integer;

    .line 6
    .line 7
    iput-object p4, p0, Ljn/m;->i:Lay0/k;

    .line 8
    .line 9
    iput-wide p5, p0, Ljn/m;->j:J

    .line 10
    .line 11
    iput-object p7, p0, Ljn/m;->k:Ljava/util/List;

    .line 12
    .line 13
    iput-object p8, p0, Ljn/m;->l:Lg4/p0;

    .line 14
    .line 15
    iput p9, p0, Ljn/m;->m:I

    .line 16
    .line 17
    const/4 p1, 0x2

    .line 18
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Ljn/m;->m:I

    .line 10
    .line 11
    or-int/lit8 v9, p1, 0x1

    .line 12
    .line 13
    iget-object v0, p0, Ljn/m;->f:Lx2/s;

    .line 14
    .line 15
    iget-object v1, p0, Ljn/m;->g:Lay0/k;

    .line 16
    .line 17
    iget-object v2, p0, Ljn/m;->h:Ljava/lang/Integer;

    .line 18
    .line 19
    iget-object v3, p0, Ljn/m;->i:Lay0/k;

    .line 20
    .line 21
    iget-wide v4, p0, Ljn/m;->j:J

    .line 22
    .line 23
    iget-object v6, p0, Ljn/m;->k:Ljava/util/List;

    .line 24
    .line 25
    iget-object v7, p0, Ljn/m;->l:Lg4/p0;

    .line 26
    .line 27
    invoke-static/range {v0 .. v9}, Llp/dc;->b(Lx2/s;Lay0/k;Ljava/lang/Integer;Lay0/k;JLjava/util/List;Lg4/p0;Ll2/o;I)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0
.end method
