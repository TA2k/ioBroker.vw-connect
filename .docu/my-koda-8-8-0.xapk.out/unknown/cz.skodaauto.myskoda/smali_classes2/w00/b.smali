.class public final synthetic Lw00/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lv00/h;

.field public final synthetic f:Z

.field public final synthetic g:Lay0/k;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lv00/h;Lay0/k;ZI)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lw00/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lw00/b;->e:Lv00/h;

    iput-object p2, p0, Lw00/b;->g:Lay0/k;

    iput-boolean p3, p0, Lw00/b;->f:Z

    iput p4, p0, Lw00/b;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lv00/h;ZLay0/k;I)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lw00/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lw00/b;->e:Lv00/h;

    iput-boolean p2, p0, Lw00/b;->f:Z

    iput-object p3, p0, Lw00/b;->g:Lay0/k;

    iput p4, p0, Lw00/b;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lw00/b;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lw00/b;->h:I

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
    iget-object v0, p0, Lw00/b;->g:Lay0/k;

    .line 22
    .line 23
    iget-object v1, p0, Lw00/b;->e:Lv00/h;

    .line 24
    .line 25
    iget-boolean p0, p0, Lw00/b;->f:Z

    .line 26
    .line 27
    invoke-static {p2, v0, p1, v1, p0}, Lw00/a;->g(ILay0/k;Ll2/o;Lv00/h;Z)V

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
    iget p2, p0, Lw00/b;->h:I

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
    iget-object v0, p0, Lw00/b;->g:Lay0/k;

    .line 42
    .line 43
    iget-object v1, p0, Lw00/b;->e:Lv00/h;

    .line 44
    .line 45
    iget-boolean p0, p0, Lw00/b;->f:Z

    .line 46
    .line 47
    invoke-static {p2, v0, p1, v1, p0}, Lw00/a;->r(ILay0/k;Ll2/o;Lv00/h;Z)V

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
