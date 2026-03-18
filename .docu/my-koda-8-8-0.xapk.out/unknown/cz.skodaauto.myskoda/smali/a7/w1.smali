.class public final La7/w1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:J

.field public final synthetic g:La7/a2;

.field public final synthetic h:Lay0/n;

.field public final synthetic i:I


# direct methods
.method public constructor <init>(IJLa7/a2;Lay0/n;)V
    .locals 0

    .line 1
    iput-wide p2, p0, La7/w1;->f:J

    .line 2
    .line 3
    iput-object p4, p0, La7/w1;->g:La7/a2;

    .line 4
    .line 5
    iput-object p5, p0, La7/w1;->h:Lay0/n;

    .line 6
    .line 7
    iput p1, p0, La7/w1;->i:I

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, La7/w1;->i:I

    .line 10
    .line 11
    or-int/lit8 v0, p1, 0x1

    .line 12
    .line 13
    iget-wide v1, p0, La7/w1;->f:J

    .line 14
    .line 15
    iget-object v3, p0, La7/w1;->g:La7/a2;

    .line 16
    .line 17
    iget-object v4, p0, La7/w1;->h:Lay0/n;

    .line 18
    .line 19
    invoke-static/range {v0 .. v5}, Lis0/b;->b(IJLa7/a2;Lay0/n;Ll2/o;)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method
