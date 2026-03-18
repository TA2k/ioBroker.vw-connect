.class public final synthetic Lxf0/p2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:F

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:F

.field public final synthetic j:Z

.field public final synthetic k:Le3/s;

.field public final synthetic l:I

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;FILjava/lang/String;FZLe3/s;III)V
    .locals 0

    .line 1
    iput p10, p0, Lxf0/p2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxf0/p2;->e:Lay0/a;

    .line 4
    .line 5
    iput p2, p0, Lxf0/p2;->f:F

    .line 6
    .line 7
    iput p3, p0, Lxf0/p2;->g:I

    .line 8
    .line 9
    iput-object p4, p0, Lxf0/p2;->h:Ljava/lang/String;

    .line 10
    .line 11
    iput p5, p0, Lxf0/p2;->i:F

    .line 12
    .line 13
    iput-boolean p6, p0, Lxf0/p2;->j:Z

    .line 14
    .line 15
    iput-object p7, p0, Lxf0/p2;->k:Le3/s;

    .line 16
    .line 17
    iput p8, p0, Lxf0/p2;->l:I

    .line 18
    .line 19
    iput p9, p0, Lxf0/p2;->m:I

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lxf0/p2;->d:I

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
    iget p1, p0, Lxf0/p2;->l:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v9

    .line 22
    iget-object v1, p0, Lxf0/p2;->e:Lay0/a;

    .line 23
    .line 24
    iget v2, p0, Lxf0/p2;->f:F

    .line 25
    .line 26
    iget v3, p0, Lxf0/p2;->g:I

    .line 27
    .line 28
    iget-object v4, p0, Lxf0/p2;->h:Ljava/lang/String;

    .line 29
    .line 30
    iget v5, p0, Lxf0/p2;->i:F

    .line 31
    .line 32
    iget-boolean v6, p0, Lxf0/p2;->j:Z

    .line 33
    .line 34
    iget-object v7, p0, Lxf0/p2;->k:Le3/s;

    .line 35
    .line 36
    iget v10, p0, Lxf0/p2;->m:I

    .line 37
    .line 38
    invoke-static/range {v1 .. v10}, Lxf0/r2;->a(Lay0/a;FILjava/lang/String;FZLe3/s;Ll2/o;II)V

    .line 39
    .line 40
    .line 41
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_0
    move-object v7, p1

    .line 45
    check-cast v7, Ll2/o;

    .line 46
    .line 47
    check-cast p2, Ljava/lang/Integer;

    .line 48
    .line 49
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    iget p1, p0, Lxf0/p2;->l:I

    .line 53
    .line 54
    or-int/lit8 p1, p1, 0x1

    .line 55
    .line 56
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 57
    .line 58
    .line 59
    move-result v8

    .line 60
    iget-object v0, p0, Lxf0/p2;->e:Lay0/a;

    .line 61
    .line 62
    iget v1, p0, Lxf0/p2;->f:F

    .line 63
    .line 64
    iget v2, p0, Lxf0/p2;->g:I

    .line 65
    .line 66
    iget-object v3, p0, Lxf0/p2;->h:Ljava/lang/String;

    .line 67
    .line 68
    iget v4, p0, Lxf0/p2;->i:F

    .line 69
    .line 70
    iget-boolean v5, p0, Lxf0/p2;->j:Z

    .line 71
    .line 72
    iget-object v6, p0, Lxf0/p2;->k:Le3/s;

    .line 73
    .line 74
    iget v9, p0, Lxf0/p2;->m:I

    .line 75
    .line 76
    invoke-static/range {v0 .. v9}, Lxf0/r2;->a(Lay0/a;FILjava/lang/String;FZLe3/s;Ll2/o;II)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
