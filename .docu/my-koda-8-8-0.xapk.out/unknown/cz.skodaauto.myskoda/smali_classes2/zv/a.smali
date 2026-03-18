.class public final Lzv/a;
.super Lretrofit2/Converter$Factory;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld01/d0;

.field public final b:Lt1/j0;


# direct methods
.method public constructor <init>(Ld01/d0;Lt1/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/Converter$Factory;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzv/a;->a:Ld01/d0;

    .line 5
    .line 6
    iput-object p2, p0, Lzv/a;->b:Lt1/j0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;[Ljava/lang/annotation/Annotation;Lretrofit2/Retrofit;)Lretrofit2/Converter;
    .locals 0

    .line 1
    const-string p2, "type"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p2, "methodAnnotations"

    .line 7
    .line 8
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p0, Lzv/a;->b:Lt1/j0;

    .line 12
    .line 13
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    iget-object p3, p2, Lt1/j0;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p3, Lqz0/j;

    .line 19
    .line 20
    check-cast p3, Lvz0/d;

    .line 21
    .line 22
    iget-object p3, p3, Lvz0/d;->b:Lwq/f;

    .line 23
    .line 24
    invoke-static {p3, p1}, Ljp/mg;->e(Lwq/f;Ljava/lang/reflect/Type;)Lqz0/a;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    new-instance p3, Lrn/i;

    .line 29
    .line 30
    iget-object p0, p0, Lzv/a;->a:Ld01/d0;

    .line 31
    .line 32
    check-cast p1, Lqz0/a;

    .line 33
    .line 34
    invoke-direct {p3, p0, p1, p2}, Lrn/i;-><init>(Ld01/d0;Lqz0/a;Lt1/j0;)V

    .line 35
    .line 36
    .line 37
    return-object p3
.end method

.method public final b(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;Lretrofit2/Retrofit;)Lretrofit2/Converter;
    .locals 0

    .line 1
    const-string p3, "annotations"

    .line 2
    .line 3
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lzv/a;->b:Lt1/j0;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object p2, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p2, Lqz0/j;

    .line 14
    .line 15
    check-cast p2, Lvz0/d;

    .line 16
    .line 17
    iget-object p2, p2, Lvz0/d;->b:Lwq/f;

    .line 18
    .line 19
    invoke-static {p2, p1}, Ljp/mg;->e(Lwq/f;Ljava/lang/reflect/Type;)Lqz0/a;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    new-instance p2, Ly7/k;

    .line 24
    .line 25
    check-cast p1, Lqz0/a;

    .line 26
    .line 27
    invoke-direct {p2, p1, p0}, Ly7/k;-><init>(Lqz0/a;Lt1/j0;)V

    .line 28
    .line 29
    .line 30
    return-object p2
.end method
