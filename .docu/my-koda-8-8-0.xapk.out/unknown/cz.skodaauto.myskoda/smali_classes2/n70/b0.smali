.class public final synthetic Ln70/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/ArrayList;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;II)V
    .locals 0

    .line 1
    iput p3, p0, Ln70/b0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln70/b0;->e:Ljava/util/ArrayList;

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
    iget v0, p0, Ln70/b0;->d:I

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
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object p0, p0, Ln70/b0;->e:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Lz10/a;->n(Ljava/util/ArrayList;Ll2/o;I)V

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    const/4 p2, 0x1

    .line 27
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    iget-object p0, p0, Ln70/b0;->e:Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-static {p0, p1, p2}, Luk/a;->g(Ljava/util/ArrayList;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :pswitch_1
    const/4 p2, 0x1

    .line 38
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    iget-object p0, p0, Ln70/b0;->e:Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-static {p0, p1, p2}, Ln70/a;->f(Ljava/util/ArrayList;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
