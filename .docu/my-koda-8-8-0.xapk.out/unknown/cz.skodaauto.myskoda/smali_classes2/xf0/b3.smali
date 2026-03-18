.class public final Lxf0/b3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvf0/i;

.field public final synthetic f:F

.field public final synthetic g:J


# direct methods
.method public constructor <init>(Lvf0/i;FJI)V
    .locals 0

    .line 1
    iput p5, p0, Lxf0/b3;->d:I

    .line 2
    .line 3
    packed-switch p5, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget p5, Lxf0/i3;->a:F

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lxf0/b3;->e:Lvf0/i;

    .line 12
    .line 13
    iput p2, p0, Lxf0/b3;->f:F

    .line 14
    .line 15
    iput-wide p3, p0, Lxf0/b3;->g:J

    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    sget p5, Lxf0/i3;->a:F

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lxf0/b3;->e:Lvf0/i;

    .line 24
    .line 25
    iput p2, p0, Lxf0/b3;->f:F

    .line 26
    .line 27
    iput-wide p3, p0, Lxf0/b3;->g:J

    .line 28
    .line 29
    return-void

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lxf0/b3;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/16 v2, 0x64

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    iget-wide v4, p0, Lxf0/b3;->g:J

    .line 9
    .line 10
    iget v6, p0, Lxf0/b3;->f:F

    .line 11
    .line 12
    iget-object p0, p0, Lxf0/b3;->e:Lvf0/i;

    .line 13
    .line 14
    const-string v7, "$this$drawBackground"

    .line 15
    .line 16
    packed-switch v0, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    check-cast p1, Lg3/d;

    .line 20
    .line 21
    invoke-static {p1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lvf0/i;->d:Lvf0/m;

    .line 25
    .line 26
    iget-object p0, p0, Lvf0/m;->a:Ljava/lang/Integer;

    .line 27
    .line 28
    if-eqz p0, :cond_0

    .line 29
    .line 30
    sget v0, Lxf0/i3;->a:F

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {p0, v3, v2}, Lkp/r9;->e(III)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    invoke-static {v6, p0, v4, v5, p1}, Lxf0/y1;->u(FIJLg3/d;)V

    .line 41
    .line 42
    .line 43
    :cond_0
    return-object v1

    .line 44
    :pswitch_0
    check-cast p1, Lg3/d;

    .line 45
    .line 46
    invoke-static {p1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object p0, p0, Lvf0/i;->c:Lvf0/m;

    .line 50
    .line 51
    iget-object p0, p0, Lvf0/m;->a:Ljava/lang/Integer;

    .line 52
    .line 53
    if-eqz p0, :cond_1

    .line 54
    .line 55
    sget v0, Lxf0/i3;->a:F

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    invoke-static {p0, v3, v2}, Lkp/r9;->e(III)I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {v6, p0, v4, v5, p1}, Lxf0/y1;->u(FIJLg3/d;)V

    .line 66
    .line 67
    .line 68
    :cond_1
    return-object v1

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
