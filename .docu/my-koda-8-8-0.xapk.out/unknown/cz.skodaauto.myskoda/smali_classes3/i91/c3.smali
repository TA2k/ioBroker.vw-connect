.class public final synthetic Li91/c3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:C

.field public final synthetic g:Li91/b3;


# direct methods
.method public synthetic constructor <init>(Lx2/s;CLi91/b3;I)V
    .locals 0

    .line 1
    const/4 p4, 0x0

    iput p4, p0, Li91/c3;->d:I

    sget-object p4, Li91/l2;->d:Li91/l2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/c3;->e:Lx2/s;

    iput-char p2, p0, Li91/c3;->f:C

    iput-object p3, p0, Li91/c3;->g:Li91/b3;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;CLi91/b3;II)V
    .locals 0

    .line 2
    iput p5, p0, Li91/c3;->d:I

    iput-object p1, p0, Li91/c3;->e:Lx2/s;

    iput-char p2, p0, Li91/c3;->f:C

    iput-object p3, p0, Li91/c3;->g:Li91/b3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Li91/c3;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    iget-object v3, p0, Li91/c3;->g:Li91/b3;

    .line 7
    .line 8
    iget-char v4, p0, Li91/c3;->f:C

    .line 9
    .line 10
    iget-object p0, p0, Li91/c3;->e:Lx2/s;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast p1, Ll2/o;

    .line 16
    .line 17
    check-cast p2, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    invoke-static {p0, v4, v3, p1, p2}, Ln70/a;->x(Lx2/s;CLi91/b3;Ll2/o;I)V

    .line 27
    .line 28
    .line 29
    return-object v2

    .line 30
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 31
    .line 32
    check-cast p2, Ljava/lang/Integer;

    .line 33
    .line 34
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    invoke-static {p0, v4, v3, p1, p2}, Ln70/a;->q0(Lx2/s;CLi91/b3;Ll2/o;I)V

    .line 42
    .line 43
    .line 44
    return-object v2

    .line 45
    :pswitch_1
    sget-object v0, Li91/l2;->d:Li91/l2;

    .line 46
    .line 47
    check-cast p1, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    const/16 p2, 0x181

    .line 55
    .line 56
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    invoke-static {p0, v4, v3, p1, p2}, Li91/j0;->d0(Lx2/s;CLi91/b3;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    return-object v2

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
