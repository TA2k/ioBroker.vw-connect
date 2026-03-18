.class public abstract Lfw0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt21/b;

.field public static final b:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "io.ktor.client.plugins.HttpRequestLifecycle"

    .line 2
    .line 3
    invoke-static {v0}, Lt21/d;->b(Ljava/lang/String;)Lt21/b;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lfw0/f0;->a:Lt21/b;

    .line 8
    .line 9
    new-instance v0, Lf31/n;

    .line 10
    .line 11
    const/16 v1, 0x1d

    .line 12
    .line 13
    invoke-direct {v0, v1}, Lf31/n;-><init>(I)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lz81/g;

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const-string v2, "RequestLifecycle"

    .line 23
    .line 24
    invoke-static {v2, v1, v0}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sput-object v0, Lfw0/f0;->b:Lgw0/c;

    .line 29
    .line 30
    return-void
.end method
