.class public final synthetic Ln70/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/util/List;

.field public final synthetic g:Z

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/util/List;ZII)V
    .locals 0

    .line 1
    iput p5, p0, Ln70/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln70/u;->e:Lx2/s;

    .line 4
    .line 5
    iput-object p2, p0, Ln70/u;->f:Ljava/util/List;

    .line 6
    .line 7
    iput-boolean p3, p0, Ln70/u;->g:Z

    .line 8
    .line 9
    iput p4, p0, Ln70/u;->h:I

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ln70/u;->d:I

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
    iget p2, p0, Ln70/u;->h:I

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
    iget-object v0, p0, Ln70/u;->e:Lx2/s;

    .line 22
    .line 23
    iget-object v1, p0, Ln70/u;->f:Ljava/util/List;

    .line 24
    .line 25
    iget-boolean p0, p0, Ln70/u;->g:Z

    .line 26
    .line 27
    invoke-static {v0, v1, p0, p1, p2}, Ln70/a;->C(Lx2/s;Ljava/util/List;ZLl2/o;I)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    iget p2, p0, Ln70/u;->h:I

    .line 34
    .line 35
    or-int/lit8 p2, p2, 0x1

    .line 36
    .line 37
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    iget-object v0, p0, Ln70/u;->e:Lx2/s;

    .line 42
    .line 43
    iget-object v1, p0, Ln70/u;->f:Ljava/util/List;

    .line 44
    .line 45
    iget-boolean p0, p0, Ln70/u;->g:Z

    .line 46
    .line 47
    invoke-static {v0, v1, p0, p1, p2}, Ln70/a;->c0(Lx2/s;Ljava/util/List;ZLl2/o;I)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
