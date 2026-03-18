.class public final Lfw0/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfw0/e1;


# instance fields
.field public final a:Lay0/o;

.field public final b:Lfw0/e1;


# direct methods
.method public constructor <init>(Lay0/o;Lfw0/e1;)V
    .locals 1

    .line 1
    const-string v0, "interceptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lfw0/u0;->a:Lay0/o;

    .line 10
    .line 11
    iput-object p2, p0, Lfw0/u0;->b:Lfw0/e1;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Lkw0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lfw0/u0;->a:Lay0/o;

    .line 2
    .line 3
    iget-object p0, p0, Lfw0/u0;->b:Lfw0/e1;

    .line 4
    .line 5
    invoke-interface {v0, p0, p1, p2}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
