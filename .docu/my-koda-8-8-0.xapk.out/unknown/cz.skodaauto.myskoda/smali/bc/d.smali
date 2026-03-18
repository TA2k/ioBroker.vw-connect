.class public final synthetic Lbc/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/util/ArrayList;

.field public final synthetic g:Ljava/util/ArrayList;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Z

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:Lbc/b;

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/util/ArrayList;Ljava/util/ArrayList;Lay0/k;ZJJLbc/b;II)V
    .locals 0

    .line 1
    iput p12, p0, Lbc/d;->d:I

    .line 2
    .line 3
    packed-switch p12, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    sget-object p12, Lbc/k;->d:[Lbc/k;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lbc/d;->e:Lx2/s;

    .line 12
    .line 13
    iput-object p2, p0, Lbc/d;->f:Ljava/util/ArrayList;

    .line 14
    .line 15
    iput-object p3, p0, Lbc/d;->g:Ljava/util/ArrayList;

    .line 16
    .line 17
    iput-object p4, p0, Lbc/d;->h:Lay0/k;

    .line 18
    .line 19
    iput-boolean p5, p0, Lbc/d;->i:Z

    .line 20
    .line 21
    iput-wide p6, p0, Lbc/d;->j:J

    .line 22
    .line 23
    iput-wide p8, p0, Lbc/d;->k:J

    .line 24
    .line 25
    iput-object p10, p0, Lbc/d;->l:Lbc/b;

    .line 26
    .line 27
    iput p11, p0, Lbc/d;->m:I

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
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lbc/d;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget v3, v0, Lbc/d;->m:I

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    sget-object v1, Lbc/k;->d:[Lbc/k;

    .line 13
    .line 14
    move-object/from16 v14, p1

    .line 15
    .line 16
    check-cast v14, Ll2/o;

    .line 17
    .line 18
    move-object/from16 v1, p2

    .line 19
    .line 20
    check-cast v1, Ljava/lang/Integer;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    or-int/lit8 v1, v3, 0x1

    .line 26
    .line 27
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 28
    .line 29
    .line 30
    move-result v15

    .line 31
    iget-object v4, v0, Lbc/d;->e:Lx2/s;

    .line 32
    .line 33
    iget-object v5, v0, Lbc/d;->f:Ljava/util/ArrayList;

    .line 34
    .line 35
    iget-object v6, v0, Lbc/d;->g:Ljava/util/ArrayList;

    .line 36
    .line 37
    iget-object v7, v0, Lbc/d;->h:Lay0/k;

    .line 38
    .line 39
    iget-boolean v8, v0, Lbc/d;->i:Z

    .line 40
    .line 41
    iget-wide v9, v0, Lbc/d;->j:J

    .line 42
    .line 43
    iget-wide v11, v0, Lbc/d;->k:J

    .line 44
    .line 45
    iget-object v13, v0, Lbc/d;->l:Lbc/b;

    .line 46
    .line 47
    invoke-static/range {v4 .. v15}, Lbc/h;->c(Lx2/s;Ljava/util/ArrayList;Ljava/util/ArrayList;Lay0/k;ZJJLbc/b;Ll2/o;I)V

    .line 48
    .line 49
    .line 50
    return-object v2

    .line 51
    :pswitch_0
    sget-object v1, Lbc/k;->d:[Lbc/k;

    .line 52
    .line 53
    move-object/from16 v14, p1

    .line 54
    .line 55
    check-cast v14, Ll2/o;

    .line 56
    .line 57
    move-object/from16 v1, p2

    .line 58
    .line 59
    check-cast v1, Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    or-int/lit8 v1, v3, 0x1

    .line 65
    .line 66
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result v15

    .line 70
    iget-object v4, v0, Lbc/d;->e:Lx2/s;

    .line 71
    .line 72
    iget-object v5, v0, Lbc/d;->f:Ljava/util/ArrayList;

    .line 73
    .line 74
    iget-object v6, v0, Lbc/d;->g:Ljava/util/ArrayList;

    .line 75
    .line 76
    iget-object v7, v0, Lbc/d;->h:Lay0/k;

    .line 77
    .line 78
    iget-boolean v8, v0, Lbc/d;->i:Z

    .line 79
    .line 80
    iget-wide v9, v0, Lbc/d;->j:J

    .line 81
    .line 82
    iget-wide v11, v0, Lbc/d;->k:J

    .line 83
    .line 84
    iget-object v13, v0, Lbc/d;->l:Lbc/b;

    .line 85
    .line 86
    invoke-static/range {v4 .. v15}, Lbc/h;->b(Lx2/s;Ljava/util/ArrayList;Ljava/util/ArrayList;Lay0/k;ZJJLbc/b;Ll2/o;I)V

    .line 87
    .line 88
    .line 89
    return-object v2

    .line 90
    nop

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
