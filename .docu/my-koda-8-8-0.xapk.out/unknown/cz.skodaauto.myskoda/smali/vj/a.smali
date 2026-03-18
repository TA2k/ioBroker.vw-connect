.class public final synthetic Lvj/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lwc/f;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lwc/f;Lay0/k;II)V
    .locals 0

    .line 1
    iput p4, p0, Lvj/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvj/a;->e:Lwc/f;

    .line 4
    .line 5
    iput-object p2, p0, Lvj/a;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lvj/a;->d:I

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
    iget-object v0, p0, Lvj/a;->f:Lay0/k;

    .line 19
    .line 20
    iget-object p0, p0, Lvj/a;->e:Lwc/f;

    .line 21
    .line 22
    invoke-static {p2, v0, p1, p0}, Lvj/c;->e(ILay0/k;Ll2/o;Lwc/f;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    const/4 p2, 0x1

    .line 29
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    iget-object v0, p0, Lvj/a;->f:Lay0/k;

    .line 34
    .line 35
    iget-object p0, p0, Lvj/a;->e:Lwc/f;

    .line 36
    .line 37
    invoke-static {p2, v0, p1, p0}, Lvj/c;->a(ILay0/k;Ll2/o;Lwc/f;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :pswitch_1
    const/4 p2, 0x1

    .line 42
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    iget-object v0, p0, Lvj/a;->f:Lay0/k;

    .line 47
    .line 48
    iget-object p0, p0, Lvj/a;->e:Lwc/f;

    .line 49
    .line 50
    invoke-static {p2, v0, p1, p0}, Lvj/c;->g(ILay0/k;Ll2/o;Lwc/f;)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :pswitch_2
    const/4 p2, 0x1

    .line 55
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    iget-object v0, p0, Lvj/a;->f:Lay0/k;

    .line 60
    .line 61
    iget-object p0, p0, Lvj/a;->e:Lwc/f;

    .line 62
    .line 63
    invoke-static {p2, v0, p1, p0}, Lvj/c;->f(ILay0/k;Ll2/o;Lwc/f;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
