.class public final synthetic Lo90/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ln90/h;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lay0/k;

.field public final synthetic p:I


# direct methods
.method public synthetic constructor <init>(Ln90/h;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo90/c;->d:Ln90/h;

    .line 5
    .line 6
    iput-object p2, p0, Lo90/c;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lo90/c;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lo90/c;->g:Lay0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lo90/c;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lo90/c;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Lo90/c;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, Lo90/c;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Lo90/c;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p10, p0, Lo90/c;->m:Lay0/k;

    .line 23
    .line 24
    iput-object p11, p0, Lo90/c;->n:Lay0/k;

    .line 25
    .line 26
    iput-object p12, p0, Lo90/c;->o:Lay0/k;

    .line 27
    .line 28
    iput p14, p0, Lo90/c;->p:I

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
    move-object/from16 v12, p1

    .line 4
    .line 5
    check-cast v12, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v13

    .line 19
    iget-object v1, v0, Lo90/c;->d:Ln90/h;

    .line 20
    .line 21
    move-object v2, v1

    .line 22
    iget-object v1, v0, Lo90/c;->e:Lay0/a;

    .line 23
    .line 24
    move-object v3, v2

    .line 25
    iget-object v2, v0, Lo90/c;->f:Lay0/a;

    .line 26
    .line 27
    move-object v4, v3

    .line 28
    iget-object v3, v0, Lo90/c;->g:Lay0/a;

    .line 29
    .line 30
    move-object v5, v4

    .line 31
    iget-object v4, v0, Lo90/c;->h:Lay0/a;

    .line 32
    .line 33
    move-object v6, v5

    .line 34
    iget-object v5, v0, Lo90/c;->i:Lay0/a;

    .line 35
    .line 36
    move-object v7, v6

    .line 37
    iget-object v6, v0, Lo90/c;->j:Lay0/a;

    .line 38
    .line 39
    move-object v8, v7

    .line 40
    iget-object v7, v0, Lo90/c;->k:Lay0/a;

    .line 41
    .line 42
    move-object v9, v8

    .line 43
    iget-object v8, v0, Lo90/c;->l:Lay0/a;

    .line 44
    .line 45
    move-object v10, v9

    .line 46
    iget-object v9, v0, Lo90/c;->m:Lay0/k;

    .line 47
    .line 48
    move-object v11, v10

    .line 49
    iget-object v10, v0, Lo90/c;->n:Lay0/k;

    .line 50
    .line 51
    move-object v14, v11

    .line 52
    iget-object v11, v0, Lo90/c;->o:Lay0/k;

    .line 53
    .line 54
    iget v0, v0, Lo90/c;->p:I

    .line 55
    .line 56
    move-object v15, v14

    .line 57
    move v14, v0

    .line 58
    move-object v0, v15

    .line 59
    invoke-static/range {v0 .. v14}, Lo90/b;->m(Ln90/h;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 60
    .line 61
    .line 62
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object v0
.end method
