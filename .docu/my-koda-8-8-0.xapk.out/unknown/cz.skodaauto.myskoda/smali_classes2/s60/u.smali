.class public final synthetic Ls60/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lr60/g0;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lr60/g0;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    iput p5, p0, Ls60/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls60/u;->e:Lr60/g0;

    .line 4
    .line 5
    iput-object p2, p0, Ls60/u;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Ls60/u;->g:Lay0/a;

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
    iget v0, p0, Ls60/u;->d:I

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
    iget-object v0, p0, Ls60/u;->e:Lr60/g0;

    .line 19
    .line 20
    iget-object v1, p0, Ls60/u;->f:Lay0/a;

    .line 21
    .line 22
    iget-object p0, p0, Ls60/u;->g:Lay0/a;

    .line 23
    .line 24
    invoke-static {v0, v1, p0, p1, p2}, Ls60/a;->z(Lr60/g0;Lay0/a;Lay0/a;Ll2/o;I)V

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
    iget-object v0, p0, Ls60/u;->e:Lr60/g0;

    .line 36
    .line 37
    iget-object v1, p0, Ls60/u;->f:Lay0/a;

    .line 38
    .line 39
    iget-object p0, p0, Ls60/u;->g:Lay0/a;

    .line 40
    .line 41
    invoke-static {v0, v1, p0, p1, p2}, Ls60/a;->z(Lr60/g0;Lay0/a;Lay0/a;Ll2/o;I)V

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
