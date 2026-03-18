.class public final Lac/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lac/f;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lac/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lac/f;->a:Lac/f;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Lac/e;)Lac/c;
    .locals 10

    .line 1
    const-string v0, "addressFormData"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lac/e;->d:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v3, p0, Lac/e;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v4, p0, Lac/e;->f:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v9, p0, Lac/e;->g:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v5, p0, Lac/e;->h:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v6, p0, Lac/e;->i:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v7, p0, Lac/e;->j:Ljava/lang/String;

    .line 19
    .line 20
    iget-object p0, p0, Lac/e;->k:Lac/a0;

    .line 21
    .line 22
    iget-object v8, p0, Lac/a0;->e:Ljava/lang/String;

    .line 23
    .line 24
    new-instance v1, Lac/c;

    .line 25
    .line 26
    invoke-direct/range {v1 .. v9}, Lac/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-object v1
.end method
