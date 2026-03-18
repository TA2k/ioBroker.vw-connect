.class public final synthetic Lvu0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:I

.field public final synthetic m:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;ZZLx2/s;Ljava/lang/String;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvu0/c;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lvu0/c;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-boolean p3, p0, Lvu0/c;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lvu0/c;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lvu0/c;->h:Lx2/s;

    .line 13
    .line 14
    iput-object p6, p0, Lvu0/c;->i:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lvu0/c;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, Lvu0/c;->k:Lay0/a;

    .line 19
    .line 20
    iput p9, p0, Lvu0/c;->l:I

    .line 21
    .line 22
    iput p10, p0, Lvu0/c;->m:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lvu0/c;->l:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v9

    .line 17
    iget-object v0, p0, Lvu0/c;->d:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Lvu0/c;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-boolean v2, p0, Lvu0/c;->f:Z

    .line 22
    .line 23
    iget-boolean v3, p0, Lvu0/c;->g:Z

    .line 24
    .line 25
    iget-object v4, p0, Lvu0/c;->h:Lx2/s;

    .line 26
    .line 27
    iget-object v5, p0, Lvu0/c;->i:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v6, p0, Lvu0/c;->j:Lay0/a;

    .line 30
    .line 31
    iget-object v7, p0, Lvu0/c;->k:Lay0/a;

    .line 32
    .line 33
    iget v10, p0, Lvu0/c;->m:I

    .line 34
    .line 35
    invoke-static/range {v0 .. v10}, Lvu0/g;->c(Ljava/lang/String;Ljava/lang/String;ZZLx2/s;Ljava/lang/String;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0
.end method
