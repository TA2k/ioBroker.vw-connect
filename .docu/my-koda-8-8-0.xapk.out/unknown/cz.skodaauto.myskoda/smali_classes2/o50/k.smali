.class public final synthetic Lo50/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ln50/b0;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Ln50/b0;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;III)V
    .locals 0

    .line 1
    iput p14, p0, Lo50/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lo50/k;->e:Ln50/b0;

    .line 4
    .line 5
    iput-object p2, p0, Lo50/k;->f:Lay0/k;

    .line 6
    .line 7
    iput-object p3, p0, Lo50/k;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Lo50/k;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Lo50/k;->i:Lay0/a;

    .line 12
    .line 13
    iput-object p6, p0, Lo50/k;->j:Lay0/a;

    .line 14
    .line 15
    iput-object p7, p0, Lo50/k;->k:Lay0/a;

    .line 16
    .line 17
    iput-object p8, p0, Lo50/k;->l:Lay0/a;

    .line 18
    .line 19
    iput-object p9, p0, Lo50/k;->m:Lay0/a;

    .line 20
    .line 21
    iput-object p10, p0, Lo50/k;->n:Lay0/a;

    .line 22
    .line 23
    iput-object p11, p0, Lo50/k;->o:Lay0/a;

    .line 24
    .line 25
    iput p13, p0, Lo50/k;->p:I

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lo50/k;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v13, p1

    .line 9
    .line 10
    check-cast v13, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 v1, 0x9

    .line 20
    .line 21
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v14

    .line 25
    iget-object v2, v0, Lo50/k;->e:Ln50/b0;

    .line 26
    .line 27
    iget-object v3, v0, Lo50/k;->f:Lay0/k;

    .line 28
    .line 29
    iget-object v4, v0, Lo50/k;->g:Lay0/a;

    .line 30
    .line 31
    iget-object v5, v0, Lo50/k;->h:Lay0/a;

    .line 32
    .line 33
    iget-object v6, v0, Lo50/k;->i:Lay0/a;

    .line 34
    .line 35
    iget-object v7, v0, Lo50/k;->j:Lay0/a;

    .line 36
    .line 37
    iget-object v8, v0, Lo50/k;->k:Lay0/a;

    .line 38
    .line 39
    iget-object v9, v0, Lo50/k;->l:Lay0/a;

    .line 40
    .line 41
    iget-object v10, v0, Lo50/k;->m:Lay0/a;

    .line 42
    .line 43
    iget-object v11, v0, Lo50/k;->n:Lay0/a;

    .line 44
    .line 45
    iget-object v12, v0, Lo50/k;->o:Lay0/a;

    .line 46
    .line 47
    iget v15, v0, Lo50/k;->p:I

    .line 48
    .line 49
    invoke-static/range {v2 .. v15}, Lo50/a;->l(Ln50/b0;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 50
    .line 51
    .line 52
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object v0

    .line 55
    :pswitch_0
    move-object/from16 v12, p1

    .line 56
    .line 57
    check-cast v12, Ll2/o;

    .line 58
    .line 59
    move-object/from16 v1, p2

    .line 60
    .line 61
    check-cast v1, Ljava/lang/Integer;

    .line 62
    .line 63
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    const/16 v1, 0x9

    .line 67
    .line 68
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 69
    .line 70
    .line 71
    move-result v13

    .line 72
    iget-object v1, v0, Lo50/k;->e:Ln50/b0;

    .line 73
    .line 74
    iget-object v2, v0, Lo50/k;->f:Lay0/k;

    .line 75
    .line 76
    iget-object v3, v0, Lo50/k;->g:Lay0/a;

    .line 77
    .line 78
    iget-object v4, v0, Lo50/k;->h:Lay0/a;

    .line 79
    .line 80
    iget-object v5, v0, Lo50/k;->i:Lay0/a;

    .line 81
    .line 82
    iget-object v6, v0, Lo50/k;->j:Lay0/a;

    .line 83
    .line 84
    iget-object v7, v0, Lo50/k;->k:Lay0/a;

    .line 85
    .line 86
    iget-object v8, v0, Lo50/k;->l:Lay0/a;

    .line 87
    .line 88
    iget-object v9, v0, Lo50/k;->m:Lay0/a;

    .line 89
    .line 90
    iget-object v10, v0, Lo50/k;->n:Lay0/a;

    .line 91
    .line 92
    iget-object v11, v0, Lo50/k;->o:Lay0/a;

    .line 93
    .line 94
    iget v14, v0, Lo50/k;->p:I

    .line 95
    .line 96
    invoke-static/range {v1 .. v14}, Lo50/a;->l(Ln50/b0;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 97
    .line 98
    .line 99
    goto :goto_0

    .line 100
    :pswitch_1
    move-object/from16 v12, p1

    .line 101
    .line 102
    check-cast v12, Ll2/o;

    .line 103
    .line 104
    move-object/from16 v1, p2

    .line 105
    .line 106
    check-cast v1, Ljava/lang/Integer;

    .line 107
    .line 108
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    const/16 v1, 0x9

    .line 112
    .line 113
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 114
    .line 115
    .line 116
    move-result v13

    .line 117
    iget-object v1, v0, Lo50/k;->e:Ln50/b0;

    .line 118
    .line 119
    iget-object v2, v0, Lo50/k;->f:Lay0/k;

    .line 120
    .line 121
    iget-object v3, v0, Lo50/k;->g:Lay0/a;

    .line 122
    .line 123
    iget-object v4, v0, Lo50/k;->h:Lay0/a;

    .line 124
    .line 125
    iget-object v5, v0, Lo50/k;->i:Lay0/a;

    .line 126
    .line 127
    iget-object v6, v0, Lo50/k;->j:Lay0/a;

    .line 128
    .line 129
    iget-object v7, v0, Lo50/k;->k:Lay0/a;

    .line 130
    .line 131
    iget-object v8, v0, Lo50/k;->l:Lay0/a;

    .line 132
    .line 133
    iget-object v9, v0, Lo50/k;->m:Lay0/a;

    .line 134
    .line 135
    iget-object v10, v0, Lo50/k;->n:Lay0/a;

    .line 136
    .line 137
    iget-object v11, v0, Lo50/k;->o:Lay0/a;

    .line 138
    .line 139
    iget v14, v0, Lo50/k;->p:I

    .line 140
    .line 141
    invoke-static/range {v1 .. v14}, Lo50/a;->l(Ln50/b0;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 142
    .line 143
    .line 144
    goto :goto_0

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
