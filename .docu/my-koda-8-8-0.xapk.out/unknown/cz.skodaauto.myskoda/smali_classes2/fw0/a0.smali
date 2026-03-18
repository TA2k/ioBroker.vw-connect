.class public abstract Lfw0/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt21/b;

.field public static final b:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "io.ktor.client.plugins.HttpPlainText"

    .line 2
    .line 3
    invoke-static {v0}, Lt21/d;->b(Ljava/lang/String;)Lt21/b;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lfw0/a0;->a:Lt21/b;

    .line 8
    .line 9
    sget-object v0, Lfw0/w;->d:Lfw0/w;

    .line 10
    .line 11
    new-instance v1, Lf31/n;

    .line 12
    .line 13
    const/16 v2, 0x1b

    .line 14
    .line 15
    invoke-direct {v1, v2}, Lf31/n;-><init>(I)V

    .line 16
    .line 17
    .line 18
    const-string v2, "HttpPlainText"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lfw0/a0;->b:Lgw0/c;

    .line 25
    .line 26
    return-void
.end method
