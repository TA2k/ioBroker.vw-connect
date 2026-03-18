.class public final synthetic Ln70/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ll70/y;

.field public final synthetic g:Lne0/s;

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:Ll70/q;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Z


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ll70/y;Lne0/s;Ljava/lang/Integer;Ll70/q;Lay0/k;ZII)V
    .locals 0

    .line 1
    iput p9, p0, Ln70/t;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln70/t;->e:Lx2/s;

    .line 4
    .line 5
    iput-object p2, p0, Ln70/t;->f:Ll70/y;

    .line 6
    .line 7
    iput-object p3, p0, Ln70/t;->g:Lne0/s;

    .line 8
    .line 9
    iput-object p4, p0, Ln70/t;->h:Ljava/lang/Integer;

    .line 10
    .line 11
    iput-object p5, p0, Ln70/t;->i:Ll70/q;

    .line 12
    .line 13
    iput-object p6, p0, Ln70/t;->j:Lay0/k;

    .line 14
    .line 15
    iput-boolean p7, p0, Ln70/t;->k:Z

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Ln70/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v8, p1

    .line 7
    check-cast v8, Ll2/o;

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
    move-result v9

    .line 19
    iget-object v1, p0, Ln70/t;->e:Lx2/s;

    .line 20
    .line 21
    iget-object v2, p0, Ln70/t;->f:Ll70/y;

    .line 22
    .line 23
    iget-object v3, p0, Ln70/t;->g:Lne0/s;

    .line 24
    .line 25
    iget-object v4, p0, Ln70/t;->h:Ljava/lang/Integer;

    .line 26
    .line 27
    iget-object v5, p0, Ln70/t;->i:Ll70/q;

    .line 28
    .line 29
    iget-object v6, p0, Ln70/t;->j:Lay0/k;

    .line 30
    .line 31
    iget-boolean v7, p0, Ln70/t;->k:Z

    .line 32
    .line 33
    invoke-static/range {v1 .. v9}, Ln70/a;->X(Lx2/s;Ll70/y;Lne0/s;Ljava/lang/Integer;Ll70/q;Lay0/k;ZLl2/o;I)V

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    move-object v7, p1

    .line 40
    check-cast v7, Ll2/o;

    .line 41
    .line 42
    check-cast p2, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    const/4 p1, 0x1

    .line 48
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    iget-object v0, p0, Ln70/t;->e:Lx2/s;

    .line 53
    .line 54
    iget-object v1, p0, Ln70/t;->f:Ll70/y;

    .line 55
    .line 56
    iget-object v2, p0, Ln70/t;->g:Lne0/s;

    .line 57
    .line 58
    iget-object v3, p0, Ln70/t;->h:Ljava/lang/Integer;

    .line 59
    .line 60
    iget-object v4, p0, Ln70/t;->i:Ll70/q;

    .line 61
    .line 62
    iget-object v5, p0, Ln70/t;->j:Lay0/k;

    .line 63
    .line 64
    iget-boolean v6, p0, Ln70/t;->k:Z

    .line 65
    .line 66
    invoke-static/range {v0 .. v8}, Ln70/a;->X(Lx2/s;Ll70/y;Lne0/s;Ljava/lang/Integer;Ll70/q;Lay0/k;ZLl2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
