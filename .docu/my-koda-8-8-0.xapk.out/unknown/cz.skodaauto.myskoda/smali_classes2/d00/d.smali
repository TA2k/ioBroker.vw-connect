.class public final synthetic Ld00/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/d0;


# direct methods
.method public synthetic constructor <init>(Lc00/d0;II)V
    .locals 0

    .line 1
    iput p3, p0, Ld00/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld00/d;->e:Lc00/d0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ld00/d;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x9

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object p0, p0, Ld00/d;->e:Lc00/d0;

    .line 20
    .line 21
    invoke-static {p0, p1, p2}, Ld00/o;->u(Lc00/d0;Ll2/o;I)V

    .line 22
    .line 23
    .line 24
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_0
    const/16 p2, 0x9

    .line 28
    .line 29
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    iget-object p0, p0, Ld00/d;->e:Lc00/d0;

    .line 34
    .line 35
    invoke-static {p0, p1, p2}, Ld00/o;->I(Lc00/d0;Ll2/o;I)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
