.class public final synthetic Lb71/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lay0/a;Lx2/s;ZI)V
    .locals 0

    .line 1
    const/4 p5, 0x1

    iput p5, p0, Lb71/q;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/q;->e:Ljava/lang/String;

    iput-object p2, p0, Lb71/q;->f:Lay0/a;

    iput-object p3, p0, Lb71/q;->g:Lx2/s;

    iput-boolean p4, p0, Lb71/q;->h:Z

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;ZLay0/a;I)V
    .locals 0

    .line 2
    const/4 p5, 0x0

    iput p5, p0, Lb71/q;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lb71/q;->g:Lx2/s;

    iput-object p2, p0, Lb71/q;->e:Ljava/lang/String;

    iput-boolean p3, p0, Lb71/q;->h:Z

    iput-object p4, p0, Lb71/q;->f:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lb71/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v4, p1

    .line 7
    check-cast v4, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget-object v2, p0, Lb71/q;->f:Lay0/a;

    .line 20
    .line 21
    iget-object v3, p0, Lb71/q;->e:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v5, p0, Lb71/q;->g:Lx2/s;

    .line 24
    .line 25
    iget-boolean v6, p0, Lb71/q;->h:Z

    .line 26
    .line 27
    invoke-static/range {v1 .. v6}, Li91/j0;->w(ILay0/a;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

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
    move-object v3, p1

    .line 34
    check-cast v3, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 p1, 0x1

    .line 42
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object v1, p0, Lb71/q;->f:Lay0/a;

    .line 47
    .line 48
    iget-object v2, p0, Lb71/q;->e:Ljava/lang/String;

    .line 49
    .line 50
    iget-object v4, p0, Lb71/q;->g:Lx2/s;

    .line 51
    .line 52
    iget-boolean v5, p0, Lb71/q;->h:Z

    .line 53
    .line 54
    invoke-static/range {v0 .. v5}, Lb71/a;->j(ILay0/a;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
