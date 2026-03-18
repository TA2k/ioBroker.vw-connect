.class public final Lvv/l;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lvv/m0;

.field public final synthetic g:Z

.field public final synthetic h:Lt2/b;

.field public final synthetic i:I


# direct methods
.method public constructor <init>(Lvv/m0;ZLt2/b;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/l;->f:Lvv/m0;

    .line 2
    .line 3
    iput-boolean p2, p0, Lvv/l;->g:Z

    .line 4
    .line 5
    iput-object p3, p0, Lvv/l;->h:Lt2/b;

    .line 6
    .line 7
    iput p4, p0, Lvv/l;->i:I

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
    .locals 2

    .line 1
    check-cast p1, Ll2/o;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    iget p2, p0, Lvv/l;->i:I

    .line 9
    .line 10
    or-int/lit8 p2, p2, 0x1

    .line 11
    .line 12
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    iget-object v0, p0, Lvv/l;->f:Lvv/m0;

    .line 17
    .line 18
    iget-boolean v1, p0, Lvv/l;->g:Z

    .line 19
    .line 20
    iget-object p0, p0, Lvv/l;->h:Lt2/b;

    .line 21
    .line 22
    invoke-static {v0, v1, p0, p1, p2}, Llp/ec;->a(Lvv/m0;ZLt2/b;Ll2/o;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0
.end method
