.class public final synthetic Lxk0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/Map;

.field public final synthetic f:Z

.field public final synthetic g:Lx2/s;


# direct methods
.method public synthetic constructor <init>(Ljava/util/Map;ZLx2/s;II)V
    .locals 0

    .line 1
    iput p5, p0, Lxk0/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxk0/n;->e:Ljava/util/Map;

    .line 4
    .line 5
    iput-boolean p2, p0, Lxk0/n;->f:Z

    .line 6
    .line 7
    iput-object p3, p0, Lxk0/n;->g:Lx2/s;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lxk0/n;->d:I

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
    iget-object v0, p0, Lxk0/n;->e:Ljava/util/Map;

    .line 19
    .line 20
    iget-boolean v1, p0, Lxk0/n;->f:Z

    .line 21
    .line 22
    iget-object p0, p0, Lxk0/n;->g:Lx2/s;

    .line 23
    .line 24
    invoke-static {v0, v1, p0, p1, p2}, Lxk0/h;->W(Ljava/util/Map;ZLx2/s;Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    const/4 p2, 0x1

    .line 31
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    iget-object v0, p0, Lxk0/n;->e:Ljava/util/Map;

    .line 36
    .line 37
    iget-boolean v1, p0, Lxk0/n;->f:Z

    .line 38
    .line 39
    iget-object p0, p0, Lxk0/n;->g:Lx2/s;

    .line 40
    .line 41
    invoke-static {v0, v1, p0, p1, p2}, Lxk0/h;->E(Ljava/util/Map;ZLx2/s;Ll2/o;I)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
