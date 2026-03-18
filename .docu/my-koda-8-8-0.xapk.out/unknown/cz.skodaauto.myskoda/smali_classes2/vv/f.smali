.class public final Lvv/f;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lvv/m0;

.field public final synthetic h:Lt2/b;

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(IILt2/b;Lvv/m0;)V
    .locals 0

    .line 1
    iput p2, p0, Lvv/f;->f:I

    .line 2
    .line 3
    iput-object p4, p0, Lvv/f;->g:Lvv/m0;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/f;->h:Lt2/b;

    .line 6
    .line 7
    iput p1, p0, Lvv/f;->i:I

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
    .locals 1

    .line 1
    iget v0, p0, Lvv/f;->f:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lvv/f;->i:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object v0, p0, Lvv/f;->g:Lvv/m0;

    .line 22
    .line 23
    iget-object p0, p0, Lvv/f;->h:Lt2/b;

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Lvv/j;->b(Lvv/m0;Lt2/b;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget p2, p0, Lvv/f;->i:I

    .line 32
    .line 33
    or-int/lit8 p2, p2, 0x1

    .line 34
    .line 35
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iget-object v0, p0, Lvv/f;->g:Lvv/m0;

    .line 40
    .line 41
    iget-object p0, p0, Lvv/f;->h:Lt2/b;

    .line 42
    .line 43
    invoke-static {v0, p0, p1, p2}, Lvv/g;->a(Lvv/m0;Lt2/b;Ll2/o;I)V

    .line 44
    .line 45
    .line 46
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
